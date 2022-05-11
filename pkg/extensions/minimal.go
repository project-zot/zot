package extensions

import (
	"reflect"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
)

type Extensions struct {
	log log.Logger
	// activated map[string]bool
}

var Ext *Extensions = &Extensions{
	log: log.NewLogger("debug", ""),
	// activated: make(map[string]bool),
}

func (e *Extensions) Invoke(meth string, args ...interface{}) []reflect.Value {
	e.log.Printf("Starting the invocation procedure for %s\n", meth)
	if !e.isActivated(meth) {
		e.log.Printf("The %s extension you are trying to use hasn't been implemented in the binary", meth)
		return []reflect.Value{
			reflect.ValueOf(errors.ErrMethodNotSupported),
		}
	}

	inputs := make([]reflect.Value, len(args))
	for i := range args {
		inputs[i] = reflect.ValueOf(args[i])
	}
	return reflect.ValueOf(e).MethodByName(meth).Call(inputs)
}

func (e *Extensions) isActivated(extension string) bool {
	if !reflect.ValueOf(Ext).MethodByName(extension).IsValid() {
		return false
	}
	e.log.Printf("The following extension is valid %v\n", extension)
	return true
}
