package common

// ImplementationManager manages implementations for a certain Plugin.
// Plugins may be invoked in 3 different ways so a manager should
// satisfy one of the following patterns:
// https://docs.openstack.org/stevedore/latest/user/essays/pycon2013.html
type ImplementationManager interface {
	RegisterImplementation(implName string, plugin interface{}) error
	AllPlugins() map[string]Plugin
	GetImpl(name string) Plugin
}
