package plugins

// PluginBuilder construct the plugin implementation, initializing
// the gRPC client with connection details and other options.
// It is needed in order to allow easy dynamic loading of the plugins.
type PluginBuilder interface {
	Build(name, addr, port string, options Options) Plugin
}
