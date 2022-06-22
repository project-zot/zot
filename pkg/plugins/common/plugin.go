package common

// A plugin is defined by an interface and a gRPC communication protocol.
// Each definition must come with an implementation that uses the gRPC client,
// a Builder that knows how to build a plugin implementation,
// a InterfaceManager that stores and dispenses implementations for the plugin.
type Plugin interface{}
