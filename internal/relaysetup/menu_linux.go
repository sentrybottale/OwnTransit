//go:build linux

package relaysetup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

func MenuInstances(ctx context.Context) ([]InstanceSummary, error) {
	root, lock, err := managerRoot(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer lock.Close()
	specs, err := scanInstances(root)
	if err != nil {
		return nil, err
	}
	var result []InstanceSummary
	for _, s := range specs {
		item := InstanceSummary{Name: s.name, URL: s.url}
		_, e := s.loadConfig()
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		item.Configured = e == nil
		if item.Configured {
			_, e = command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", s.unitName)
			item.Running = e == nil
		}
		result = append(result, item)
	}
	return result, nil
}

func menuInstance(root *securefs.Root, url string) (instanceSpec, error) {
	canonical, err := PublicURL(url)
	if err != nil || canonical != url {
		return instanceSpec{}, ErrRoute
	}
	specs, err := scanInstances(root)
	if err != nil {
		return instanceSpec{}, err
	}
	for _, s := range specs {
		if s.url == url {
			return s, nil
		}
	}
	return instanceSpec{}, errors.New("configure this relay URL first")
}

func loadMenuPlans(root *securefs.Root, url string) (tunnelPlans, error) {
	var p tunnelPlans
	b, err := root.ReadFile(menuPlanFile, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return tunnelPlans{Schema: "owntransit.relay-menu.v1", URL: url, Items: []tunnelPlan{}}, nil
	}
	if err != nil {
		return p, err
	}
	if strictjson.Decode(b, &p) != nil || !p.valid(url) {
		return p, errors.New("local tunnel menu state is invalid")
	}
	return p, nil
}

func saveMenuPlans(root *securefs.Root, p tunnelPlans) error {
	if !p.valid(p.URL) {
		return errors.New("invalid tunnel menu state")
	}
	b, err := json.Marshal(p)
	if err != nil || len(b) > 64<<10 {
		return errors.New("tunnel menu state exceeds its bound")
	}
	return root.ReplaceFile(menuPlanFile, b, 0600)
}

func (s instanceSpec) menuControl(ctx context.Context, operation string, args ...string) ([]byte, error) {
	c, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	if err = s.validateData(); err != nil {
		return nil, err
	}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = noPendingOperation(root); err != nil {
		return nil, err
	}
	if _, err = s.managedIdentity(ctx, c.Engine, c.Image); err != nil {
		return nil, err
	}
	commandArgs := []string{"exec", s.container, "/owntransit-relay", operation, "--state", "/state/relay"}
	commandArgs = append(commandArgs, args...)
	return command(ctx, c.Engine, commandArgs...)
}

func (s instanceSpec) admissions(ctx context.Context) ([]pairrelay.AdmissionInfo, error) {
	b, err := s.menuControl(ctx, "admissions")
	if err != nil {
		return nil, err
	}
	var items []pairrelay.AdmissionInfo
	if len(b) > 256<<10 || strictjson.Decode(b, &items) != nil || len(items) > 256 {
		return nil, errors.New("invalid bounded relay inventory")
	}
	seen := map[string]bool{}
	for _, item := range items {
		t := MenuTunnel{ReceiverID: item.ReceiverID, RouteID: item.RouteID, Status: item.Status, Active: item.ActiveCarriers}
		if !validMenuTunnel(t) || seen[t.ReceiverID] {
			return nil, errors.New("invalid relay tunnel identity")
		}
		seen[t.ReceiverID] = true
	}
	return items, nil
}

func MenuTunnels(ctx context.Context, url string) ([]MenuTunnel, error) {
	packageLock, err := LockPackage(0)
	if err != nil {
		return nil, err
	}
	defer packageLock.Close()
	root, lock, err := managerRoot(false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer lock.Close()
	s, err := menuInstance(root, url)
	if err != nil {
		return nil, err
	}
	selected, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer selected.Close()
	p, err := loadMenuPlans(selected, url)
	if err != nil {
		return nil, err
	}
	admissions, err := s.admissions(ctx)
	if err != nil {
		return nil, errors.New("relay inventory unavailable; configure or restart this relay first")
	}
	byID := map[string]pairrelay.AdmissionInfo{}
	for _, item := range admissions {
		byID[item.ReceiverID] = item
	}
	var result []MenuTunnel
	for _, plan := range p.Items {
		t := MenuTunnel{Name: plan.Name, ReceiverID: plan.ReceiverID, RouteID: plan.RouteID, Status: "under construction"}
		if plan.ReceiverID != "" {
			t.Status = "unavailable"
			if a, ok := byID[plan.ReceiverID]; ok {
				if a.RouteID != plan.RouteID {
					return nil, errors.New("stored tunnel route changed")
				}
				t.Status, t.Active = a.Status, a.ActiveCarriers
				delete(byID, plan.ReceiverID)
			}
		}
		result = append(result, t)
	}
	for _, a := range byID {
		result = append(result, MenuTunnel{ReceiverID: a.ReceiverID, RouteID: a.RouteID, Status: a.Status, Active: a.ActiveCarriers})
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ReceiverID < b.ReceiverID
	})
	return result, nil
}

func NewMenuTunnel(ctx context.Context, url, name string) error {
	if err := boundedMenuName(name); err != nil {
		return err
	}
	packageLock, err := LockPackage(0)
	if err != nil {
		return err
	}
	defer packageLock.Close()
	root, lock, err := managerRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	s, err := menuInstance(root, url)
	if err != nil {
		return err
	}
	selected, err := s.openRoot()
	if err != nil {
		return err
	}
	defer selected.Close()
	if _, err = s.loadConfig(); err != nil {
		return err
	}
	if err = noPendingOperation(selected); err != nil {
		return err
	}
	p, err := loadMenuPlans(selected, url)
	if err != nil {
		return err
	}
	for _, item := range p.Items {
		if item.Name == name {
			return errors.New("name already exists; choose Continue tunnel")
		}
	}
	if len(p.Items) >= maxMenuTunnels {
		return errors.New("local tunnel plan limit reached")
	}
	p.Items = append(p.Items, tunnelPlan{Name: name})
	return saveMenuPlans(selected, p)
}

func ApproveMenuTunnel(ctx context.Context, url, name, id string) error {
	if err := boundedMenuName(name); err != nil {
		return err
	}
	if err := validatePublicReceiverID(id); err != nil {
		return err
	}
	packageLock, err := LockPackage(0)
	if err != nil {
		return err
	}
	defer packageLock.Close()
	root, lock, err := managerRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	s, err := menuInstance(root, url)
	if err != nil {
		return err
	}
	selected, err := s.openRoot()
	if err != nil {
		return err
	}
	defer selected.Close()
	p, err := loadMenuPlans(selected, url)
	if err != nil {
		return err
	}
	index := -1
	for i, item := range p.Items {
		if item.Name == name {
			index = i
			if item.ReceiverID != "" {
				return errors.New("this tunnel already has a target; continue from the Client")
			}
		}
		if item.Name != name && item.ReceiverID == id {
			return errors.New("target belongs to another local tunnel name")
		}
	}
	if index < 0 {
		return errors.New("tunnel plan no longer exists")
	}
	code, err := s.register(ctx, id)
	if err != nil {
		return err
	}
	registration, err := pairrelaycmd.DecodeRegistration(code)
	if err != nil || registration.ReceiverID.String() != id {
		return errors.New("invalid local relay approval response")
	}
	if old := p.Items[index]; old.RouteID != "" && old.RouteID != registration.RouteID.String() {
		return errors.New("target route changed; no local binding was overwritten")
	}
	p.Items[index].ReceiverID, p.Items[index].RouteID = id, registration.RouteID.String()
	if err := saveMenuPlans(selected, p); err != nil {
		return errors.Join(ErrMenuApprovalSaved, err)
	}
	return nil
}

func RemoveMenuTunnel(ctx context.Context, url string, want MenuTunnel) error {
	if !validMenuTunnel(want) {
		return errors.New("invalid selected tunnel")
	}
	packageLock, err := LockPackage(0)
	if err != nil {
		return err
	}
	defer packageLock.Close()
	root, lock, err := managerRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	s, err := menuInstance(root, url)
	if err != nil {
		return err
	}
	selected, err := s.openRoot()
	if err != nil {
		return err
	}
	defer selected.Close()
	if err = noPendingOperation(selected); err != nil {
		return err
	}
	p, err := loadMenuPlans(selected, url)
	if err != nil {
		return err
	}
	index := -1
	if want.Name != "" {
		for i, item := range p.Items {
			if item.Name == want.Name {
				index = i
				if item.ReceiverID != want.ReceiverID || item.RouteID != want.RouteID {
					return errors.New("selected tunnel changed; select it again")
				}
			}
		}
		if index < 0 {
			return errors.New("selected tunnel no longer exists")
		}
	}
	if want.ReceiverID != "" {
		items, err := s.admissions(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, item := range items {
			if item.ReceiverID == want.ReceiverID && item.RouteID == want.RouteID {
				found = true
			}
		}
		if !found {
			if index >= 0 {
				p.Items = append(p.Items[:index], p.Items[index+1:]...)
				if err := saveMenuPlans(selected, p); err != nil {
					return err
				}
				return ErrMenuPlanRemoved
			}
			return errors.New("selected relay admission no longer exists")
		}
		if _, err = s.menuControl(ctx, "remove-admission", "--receiver", want.ReceiverID, "--route", want.RouteID); err != nil {
			return err
		}
	}
	if index >= 0 {
		p.Items = append(p.Items[:index], p.Items[index+1:]...)
		return saveMenuPlans(selected, p)
	}
	return nil
}
