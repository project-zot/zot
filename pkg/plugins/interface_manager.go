package plugins

// InterfaceManager manages implementations for a certain Plugin.
// Plugins may be invoked in 3 different ways so a manager should
// satisfy one of the following patterns:
// https://docs.openstack.org/stevedore/latest/user/essays/pycon2013.html#:~:text=%E2%80%9CDrivers%E2%80%9D%20are%20loaded%20one%20at%20a%20time%2C%20and%20used%20directly.
type InterfaceManager interface {
	RegisterImplementation(implName string, plugin interface{}) error
	AllPlugins() map[string]Plugin
}
