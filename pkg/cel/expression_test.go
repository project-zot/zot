/*
Copyright 2025 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Copied from:
// https://github.com/fluxcd/pkg/blob/d6af17e6f40bfdd628ab1f7793bc878d5d90e8b6/runtime/cel/expression_test.go

//nolint:all // Code copied from external project
package cel_test

import (
	"context"
	"testing"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	. "github.com/onsi/gomega"

	"zotregistry.dev/zot/v2/pkg/cel"
)

func TestNewExpression(t *testing.T) {
	for _, tt := range []struct {
		name string
		expr string
		opts []cel.Option
		err  string
	}{
		{
			name: "valid expression",
			expr: "foo",
		},
		{
			name: "invalid expression",
			expr: "foo.",
			err:  "failed to parse the CEL expression 'foo.': ERROR: <input>:1:5: Syntax error: no viable alternative at input '.'",
		},
		{
			name: "compilation detects undeclared references",
			expr: "foo",
			opts: []cel.Option{cel.WithCompile()},
			err:  "failed to parse the CEL expression 'foo': ERROR: <input>:1:1: undeclared reference to 'foo'",
		},
		{
			name: "compilation detects type errors",
			expr: "foo == 'bar'",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			err:  "failed to parse the CEL expression 'foo == 'bar'': ERROR: <input>:1:5: found no matching overload for '_==_' applied to '(map(string, dyn), string)'",
		},
		{
			name: "can't check output type without compiling",
			expr: "foo",
			opts: []cel.Option{cel.WithOutputType(celgo.BoolType)},
			err:  "output type and variables can only be set when compiling the expression",
		},
		{
			name: "can't declare variables without compiling",
			expr: "foo",
			opts: []cel.Option{cel.WithStructVariables("foo")},
			err:  "output type and variables can only be set when compiling the expression",
		},
		{
			name: "compilation checks output type",
			expr: "'foo'",
			opts: []cel.Option{cel.WithCompile(), cel.WithOutputType(celgo.BoolType)},
			err:  "CEL expression output type mismatch: expected bool, got string",
		},
		{
			name: "compilation checking output type can't predict type of struct field",
			expr: "foo.bar.baz",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo"), cel.WithOutputType(celgo.BoolType)},
			err:  "CEL expression output type mismatch: expected bool, got dyn",
		},
		{
			name: "compilation checking output type can't predict type of struct field, but if it's a boolean it can be compared to a boolean literal",
			expr: "foo.bar.baz == true",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo"), cel.WithOutputType(celgo.BoolType)},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g := NewWithT(t)

			e, err := cel.NewExpression(tt.expr, tt.opts...)

			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
				g.Expect(e).To(BeNil())
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(e).NotTo(BeNil())
			}
		})
	}
}

func TestExpression_EvaluateBoolean(t *testing.T) {
	for _, tt := range []struct {
		name   string
		expr   string
		opts   []cel.Option
		data   map[string]any
		result bool
		err    string
	}{
		{
			name: "inexistent field",
			expr: "foo",
			data: map[string]any{},
			err:  "failed to evaluate the CEL expression 'foo': no such attribute(s): foo",
		},
		{
			name:   "boolean field true",
			expr:   "foo",
			data:   map[string]any{"foo": true},
			result: true,
		},
		{
			name:   "boolean field false",
			expr:   "foo",
			data:   map[string]any{"foo": false},
			result: false,
		},
		{
			name:   "nested boolean field true",
			expr:   "foo.bar",
			data:   map[string]any{"foo": map[string]any{"bar": true}},
			result: true,
		},
		{
			name:   "nested boolean field false",
			expr:   "foo.bar",
			data:   map[string]any{"foo": map[string]any{"bar": false}},
			result: false,
		},
		{
			name:   "boolean literal true",
			expr:   "true",
			data:   map[string]any{},
			result: true,
		},
		{
			name:   "boolean literal false",
			expr:   "false",
			data:   map[string]any{},
			result: false,
		},
		{
			name: "non-boolean literal",
			expr: "'some-value'",
			data: map[string]any{},
			err:  "failed to evaluate CEL expression as boolean: ''some-value''",
		},
		{
			name: "non-boolean field",
			expr: "foo",
			data: map[string]any{"foo": "some-value"},
			err:  "failed to evaluate CEL expression as boolean: 'foo'",
		},
		{
			name: "nested non-boolean field",
			expr: "foo.bar",
			data: map[string]any{"foo": map[string]any{"bar": "some-value"}},
			err:  "failed to evaluate CEL expression as boolean: 'foo.bar'",
		},
		{
			name:   "complex expression evaluating true",
			expr:   "foo && bar",
			data:   map[string]any{"foo": true, "bar": true},
			result: true,
		},
		{
			name:   "complex expression evaluating false",
			expr:   "foo && bar",
			data:   map[string]any{"foo": true, "bar": false},
			result: false,
		},
		{
			name:   "compiled expression returning true",
			expr:   "foo.bar",
			opts:   []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data:   map[string]any{"foo": map[string]any{"bar": true}},
			result: true,
		},
		{
			name:   "compiled expression returning false",
			expr:   "foo.bar",
			opts:   []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data:   map[string]any{"foo": map[string]any{"bar": false}},
			result: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g := NewWithT(t)

			e, err := cel.NewExpression(tt.expr, tt.opts...)
			g.Expect(err).NotTo(HaveOccurred())

			result, err := e.EvaluateBoolean(context.Background(), tt.data)

			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(result).To(Equal(tt.result))
			}
		})
	}
}

func TestExpression_EvaluateString(t *testing.T) {
	for _, tt := range []struct {
		name   string
		expr   string
		opts   []cel.Option
		data   map[string]any
		result string
		err    string
	}{
		{
			name: "non-existent field",
			expr: "foo",
			data: map[string]any{},
			err:  "failed to evaluate the CEL expression 'foo': no such attribute(s): foo",
		},
		{
			name:   "string field",
			expr:   "foo",
			data:   map[string]any{"foo": "some-value"},
			result: "some-value",
		},
		{
			name: "non-string field",
			expr: "foo",
			data: map[string]any{"foo": 123},
			err:  "failed to evaluate CEL expression as string: 'foo'",
		},
		{
			name:   "nested string field",
			expr:   "foo.bar",
			data:   map[string]any{"foo": map[string]any{"bar": "some-value"}},
			result: "some-value",
		},
		{
			name:   "compiled expression returning string",
			expr:   "foo.bar",
			opts:   []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data:   map[string]any{"foo": map[string]any{"bar": "some-value"}},
			result: "some-value",
		},
		{
			name: "compiled expression returning string multiple variables",
			expr: "foo.bar + '/' + foo.baz + '/' + bar.biz",
			opts: []cel.Option{
				cel.WithCompile(),
				cel.WithStructVariables("foo", "bar"),
			},
			data: map[string]any{
				"foo": map[string]any{
					"bar": "some-value",
					"baz": "some-other-value"},
				"bar": map[string]any{
					"biz": "some-third-value",
				},
			},
			result: "some-value/some-other-value/some-third-value",
		},
		{
			name: "compiled expression with string manipulation and zero index",
			expr: "foo.bar + '/' + foo.baz + '/' + bar.uid.split('-')[0].lowerAscii()",
			opts: []cel.Option{
				cel.WithCompile(),
				cel.WithStructVariables("foo", "bar"),
			},
			data: map[string]any{
				"foo": map[string]any{
					"bar": "some-value",
					"baz": "some-other-value"},
				"bar": map[string]any{
					"uid": "AKS2J23-DAFLSDD-123J5LS",
				},
			},
			result: "some-value/some-other-value/aks2j23",
		},
		{
			name: "compiled expression with string manipulation and first",
			expr: "foo.bar + '/' + foo.baz + '/' + bar.uid.split('-').first().value().lowerAscii()",
			opts: []cel.Option{
				cel.WithCompile(),
				cel.WithStructVariables("foo", "bar"),
			},
			data: map[string]any{
				"foo": map[string]any{
					"bar": "some-value",
					"baz": "some-other-value"},
				"bar": map[string]any{
					"uid": "AKS2J23-DAFLSDD-123J5LS",
				},
			},
			result: "some-value/some-other-value/aks2j23",
		},
		{
			name: "compiled expression with first",
			expr: "foo.bar.split('-').first().value()",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{"bar": "hello-world-testing-123"},
			},
			result: "hello",
		},
		{
			name: "compiled expression with last",
			expr: "foo.bar.split('-').last().value()",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{"bar": "hello-world-testing-123"},
			},
			result: "123",
		},
		{
			name: "error without value method",
			expr: "foo.bar.split('-').first()",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{"bar": "hello-world-testing-123"},
			},
			err: "failed to evaluate CEL expression as string: 'foo.bar.split('-').first()'",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g := NewWithT(t)

			e, err := cel.NewExpression(tt.expr, tt.opts...)
			g.Expect(err).NotTo(HaveOccurred())

			result, err := e.EvaluateString(context.Background(), tt.data)

			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(result).To(Equal(tt.result))
			}
		})
	}
}

func TestExpression_EvaluateStringSlice(t *testing.T) {
	for _, tt := range []struct {
		name   string
		expr   string
		opts   []cel.Option
		data   map[string]any
		result []string
		err    string
	}{
		{
			name: "non-existent field",
			expr: "foo",
			data: map[string]any{},
			err:  "failed to evaluate the CEL expression 'foo': no such attribute(s): foo",
		},
		{
			name:   "string slice field",
			expr:   "foo",
			data:   map[string]any{"foo": []string{"value1", "value2", "value3"}},
			result: []string{"value1", "value2", "value3"},
		},
		{
			name:   "empty string slice field",
			expr:   "foo",
			data:   map[string]any{"foo": []string{}},
			result: []string{},
		},
		{
			name: "non-slice field",
			expr: "foo",
			data: map[string]any{"foo": "not-a-slice"},
			err:  "failed to evaluate CEL expression 'foo' as []string: unsupported native conversion from string to '[]string'",
		},
		{
			name: "non-string slice field",
			expr: "foo",
			data: map[string]any{"foo": []int{1, 2, 3}},
			err:  "failed to evaluate CEL expression 'foo' as []string: unsupported type conversion from 'int' to string",
		},
		{
			name:   "nested any slice field",
			expr:   "foo.bar",
			data:   map[string]any{"foo": map[string]any{"bar": []any{"nested1", "nested2"}}},
			result: []string{"nested1", "nested2"},
		},
		{
			name:   "string slice literal",
			expr:   "['literal1', 'literal2', 'literal3']",
			data:   map[string]any{},
			result: []string{"literal1", "literal2", "literal3"},
		},
		{
			name:   "compiled expression returning string slice",
			expr:   "foo.bar",
			opts:   []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data:   map[string]any{"foo": map[string]any{"bar": []string{"compiled1", "compiled2"}}},
			result: []string{"compiled1", "compiled2"},
		},
		{
			name: "compiled expression with string manipulation returning slice",
			expr: "foo.items.map(item, item.upperAscii())",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{
					"items": []string{"hello", "world", "test"},
				},
			},
			result: []string{"HELLO", "WORLD", "TEST"},
		},
		{
			name: "compiled expression with filter returning slice",
			expr: "foo.items.filter(item, item.startsWith('t'))",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{
					"items": []string{"hello", "test", "world", "testing"},
				},
			},
			result: []string{"test", "testing"},
		},
		{
			name: "compiled expression with split returning slice",
			expr: "foo.value.split(',')",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{
					"value": "item1,item2,item3",
				},
			},
			result: []string{"item1", "item2", "item3"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g := NewWithT(t)

			e, err := cel.NewExpression(tt.expr, tt.opts...)
			g.Expect(err).NotTo(HaveOccurred())

			result, err := e.EvaluateStringSlice(context.Background(), tt.data)

			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(result).To(Equal(tt.result))
			}
		})
	}
}

func TestExpression_Evaluate(t *testing.T) {
	for _, tt := range []struct {
		name   string
		expr   string
		opts   []cel.Option
		data   map[string]any
		result any
		err    string
	}{
		{
			name: "non-existent field",
			expr: "foo",
			data: map[string]any{},
			err:  "failed to evaluate the CEL expression 'foo': no such attribute(s): foo",
		},
		{
			name:   "string slice field",
			expr:   "foo",
			data:   map[string]any{"foo": []string{"value1", "value2", "value3"}},
			result: []string{"value1", "value2", "value3"},
		},
		{
			name:   "empty string slice field",
			expr:   "foo",
			data:   map[string]any{"foo": []string{}},
			result: []string{},
		},
		{
			name:   "non-slice field",
			expr:   "foo",
			data:   map[string]any{"foo": "not-a-slice"},
			result: "not-a-slice",
		},
		{
			name:   "non-string slice field",
			expr:   "foo",
			data:   map[string]any{"foo": []int{1, 2, 3}},
			result: []int{1, 2, 3},
		},
		{
			name:   "nested any slice field",
			expr:   "foo.bar",
			data:   map[string]any{"foo": map[string]any{"bar": []any{"nested1", "nested2"}}},
			result: []any{"nested1", "nested2"},
		},
		{
			name:   "string slice literal",
			expr:   "['literal1', 'literal2', 'literal3']",
			data:   map[string]any{},
			result: []ref.Val{types.String("literal1"), types.String("literal2"), types.String("literal3")},
		},
		{
			name:   "compiled expression returning string slice",
			expr:   "foo.bar",
			opts:   []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data:   map[string]any{"foo": map[string]any{"bar": []string{"compiled1", "compiled2"}}},
			result: []string{"compiled1", "compiled2"},
		},
		{
			name: "compiled expression with string manipulation returning slice",
			expr: "foo.items.map(item, item.upperAscii())",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{
					"items": []string{"hello", "world", "test"},
				},
			},
			result: []ref.Val{types.String("HELLO"), types.String("WORLD"), types.String("TEST")},
		},
		{
			name: "compiled expression with filter returning slice",
			expr: "foo.items.filter(item, item.startsWith('t'))",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{
					"items": []string{"hello", "test", "world", "testing"},
				},
			},
			result: []ref.Val{types.String("test"), types.String("testing")},
		},
		{
			name: "compiled expression with split returning slice",
			expr: "foo.value.split(',')",
			opts: []cel.Option{cel.WithCompile(), cel.WithStructVariables("foo")},
			data: map[string]any{
				"foo": map[string]any{
					"value": "item1,item2,item3",
				},
			},
			result: []string{"item1", "item2", "item3"},
		},
		{
			name: "expression returning a map",
			expr: "foo.bar",
			data: map[string]any{
				"foo": map[string]any{
					"bar": map[string]any{
						"value": "item1,item2,item3",
					},
				},
			},
			result: map[string]any{
				"value": "item1,item2,item3",
			},
		},
		{
			name: "expression returning a map with a string slice inside",
			expr: "foo.bar",
			data: map[string]any{
				"foo": map[string]any{
					"bar": map[string]any{
						"value": []string{"item1", "item2", "item3"},
					},
				},
			},
			result: map[string]any{
				"value": []string{"item1", "item2", "item3"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g := NewWithT(t)

			e, err := cel.NewExpression(tt.expr, tt.opts...)
			g.Expect(err).NotTo(HaveOccurred())

			result, err := e.Evaluate(context.Background(), tt.data)

			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(result).To(Equal(tt.result))
			}
		})
	}
}
