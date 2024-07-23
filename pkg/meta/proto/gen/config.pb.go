// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.24.4
// source: oci/config.proto

package gen

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Image struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Created  *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=Created,proto3,oneof" json:"Created,omitempty"`
	Author   *string                `protobuf:"bytes,2,opt,name=Author,proto3,oneof" json:"Author,omitempty"`
	Platform *Platform              `protobuf:"bytes,3,opt,name=Platform,proto3" json:"Platform,omitempty"`
	Config   *ImageConfig           `protobuf:"bytes,4,opt,name=Config,proto3,oneof" json:"Config,omitempty"`
	RootFS   *RootFS                `protobuf:"bytes,5,opt,name=RootFS,proto3,oneof" json:"RootFS,omitempty"`
	History  []*History             `protobuf:"bytes,6,rep,name=History,proto3" json:"History,omitempty"`
}

func (x *Image) Reset() {
	*x = Image{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oci_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Image) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Image) ProtoMessage() {}

func (x *Image) ProtoReflect() protoreflect.Message {
	mi := &file_oci_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Image.ProtoReflect.Descriptor instead.
func (*Image) Descriptor() ([]byte, []int) {
	return file_oci_config_proto_rawDescGZIP(), []int{0}
}

func (x *Image) GetCreated() *timestamppb.Timestamp {
	if x != nil {
		return x.Created
	}
	return nil
}

func (x *Image) GetAuthor() string {
	if x != nil && x.Author != nil {
		return *x.Author
	}
	return ""
}

func (x *Image) GetPlatform() *Platform {
	if x != nil {
		return x.Platform
	}
	return nil
}

func (x *Image) GetConfig() *ImageConfig {
	if x != nil {
		return x.Config
	}
	return nil
}

func (x *Image) GetRootFS() *RootFS {
	if x != nil {
		return x.RootFS
	}
	return nil
}

func (x *Image) GetHistory() []*History {
	if x != nil {
		return x.History
	}
	return nil
}

type ImageConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ExposedPorts map[string]*EmptyMessage `protobuf:"bytes,1,rep,name=ExposedPorts,proto3" json:"ExposedPorts,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Volumes      map[string]*EmptyMessage `protobuf:"bytes,2,rep,name=Volumes,proto3" json:"Volumes,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Labels       map[string]string        `protobuf:"bytes,3,rep,name=Labels,proto3" json:"Labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	User         string                   `protobuf:"bytes,4,opt,name=User,proto3" json:"User,omitempty"`
	Env          []string                 `protobuf:"bytes,5,rep,name=Env,proto3" json:"Env,omitempty"`
	Entrypoint   []string                 `protobuf:"bytes,6,rep,name=Entrypoint,proto3" json:"Entrypoint,omitempty"`
	Cmd          []string                 `protobuf:"bytes,7,rep,name=Cmd,proto3" json:"Cmd,omitempty"`
	WorkingDir   *string                  `protobuf:"bytes,8,opt,name=WorkingDir,proto3,oneof" json:"WorkingDir,omitempty"`
	StopSignal   *string                  `protobuf:"bytes,9,opt,name=StopSignal,proto3,oneof" json:"StopSignal,omitempty"`
	ArgsEscaped  bool                     `protobuf:"varint,10,opt,name=ArgsEscaped,proto3" json:"ArgsEscaped,omitempty"`
}

func (x *ImageConfig) Reset() {
	*x = ImageConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oci_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImageConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImageConfig) ProtoMessage() {}

func (x *ImageConfig) ProtoReflect() protoreflect.Message {
	mi := &file_oci_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImageConfig.ProtoReflect.Descriptor instead.
func (*ImageConfig) Descriptor() ([]byte, []int) {
	return file_oci_config_proto_rawDescGZIP(), []int{1}
}

func (x *ImageConfig) GetExposedPorts() map[string]*EmptyMessage {
	if x != nil {
		return x.ExposedPorts
	}
	return nil
}

func (x *ImageConfig) GetVolumes() map[string]*EmptyMessage {
	if x != nil {
		return x.Volumes
	}
	return nil
}

func (x *ImageConfig) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *ImageConfig) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *ImageConfig) GetEnv() []string {
	if x != nil {
		return x.Env
	}
	return nil
}

func (x *ImageConfig) GetEntrypoint() []string {
	if x != nil {
		return x.Entrypoint
	}
	return nil
}

func (x *ImageConfig) GetCmd() []string {
	if x != nil {
		return x.Cmd
	}
	return nil
}

func (x *ImageConfig) GetWorkingDir() string {
	if x != nil && x.WorkingDir != nil {
		return *x.WorkingDir
	}
	return ""
}

func (x *ImageConfig) GetStopSignal() string {
	if x != nil && x.StopSignal != nil {
		return *x.StopSignal
	}
	return ""
}

func (x *ImageConfig) GetArgsEscaped() bool {
	if x != nil {
		return x.ArgsEscaped
	}
	return false
}

type RootFS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type    string   `protobuf:"bytes,1,opt,name=Type,proto3" json:"Type,omitempty"`
	DiffIDs []string `protobuf:"bytes,2,rep,name=DiffIDs,proto3" json:"DiffIDs,omitempty"`
}

func (x *RootFS) Reset() {
	*x = RootFS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oci_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RootFS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RootFS) ProtoMessage() {}

func (x *RootFS) ProtoReflect() protoreflect.Message {
	mi := &file_oci_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RootFS.ProtoReflect.Descriptor instead.
func (*RootFS) Descriptor() ([]byte, []int) {
	return file_oci_config_proto_rawDescGZIP(), []int{2}
}

func (x *RootFS) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *RootFS) GetDiffIDs() []string {
	if x != nil {
		return x.DiffIDs
	}
	return nil
}

type History struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Created    *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=Created,proto3,oneof" json:"Created,omitempty"`
	CreatedBy  *string                `protobuf:"bytes,2,opt,name=CreatedBy,proto3,oneof" json:"CreatedBy,omitempty"`
	Author     *string                `protobuf:"bytes,3,opt,name=Author,proto3,oneof" json:"Author,omitempty"`
	Comment    *string                `protobuf:"bytes,4,opt,name=Comment,proto3,oneof" json:"Comment,omitempty"`
	EmptyLayer *bool                  `protobuf:"varint,5,opt,name=EmptyLayer,proto3,oneof" json:"EmptyLayer,omitempty"`
}

func (x *History) Reset() {
	*x = History{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oci_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *History) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*History) ProtoMessage() {}

func (x *History) ProtoReflect() protoreflect.Message {
	mi := &file_oci_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use History.ProtoReflect.Descriptor instead.
func (*History) Descriptor() ([]byte, []int) {
	return file_oci_config_proto_rawDescGZIP(), []int{3}
}

func (x *History) GetCreated() *timestamppb.Timestamp {
	if x != nil {
		return x.Created
	}
	return nil
}

func (x *History) GetCreatedBy() string {
	if x != nil && x.CreatedBy != nil {
		return *x.CreatedBy
	}
	return ""
}

func (x *History) GetAuthor() string {
	if x != nil && x.Author != nil {
		return *x.Author
	}
	return ""
}

func (x *History) GetComment() string {
	if x != nil && x.Comment != nil {
		return *x.Comment
	}
	return ""
}

func (x *History) GetEmptyLayer() bool {
	if x != nil && x.EmptyLayer != nil {
		return *x.EmptyLayer
	}
	return false
}

type EmptyMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EmptyMessage) Reset() {
	*x = EmptyMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oci_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EmptyMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EmptyMessage) ProtoMessage() {}

func (x *EmptyMessage) ProtoReflect() protoreflect.Message {
	mi := &file_oci_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EmptyMessage.ProtoReflect.Descriptor instead.
func (*EmptyMessage) Descriptor() ([]byte, []int) {
	return file_oci_config_proto_rawDescGZIP(), []int{4}
}

var File_oci_config_proto protoreflect.FileDescriptor

var file_oci_config_proto_rawDesc = []byte{
	0x0a, 0x10, 0x6f, 0x63, 0x69, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x06, 0x6f, 0x63, 0x69, 0x5f, 0x76, 0x31, 0x1a, 0x13, 0x6f, 0x63, 0x69, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x14, 0x6f, 0x63, 0x69, 0x2f, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc4, 0x02, 0x0a, 0x05, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x12,
	0x39, 0x0a, 0x07, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x48, 0x00, 0x52, 0x07,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x88, 0x01, 0x01, 0x12, 0x1b, 0x0a, 0x06, 0x41, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x06, 0x41, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x88, 0x01, 0x01, 0x12, 0x2c, 0x0a, 0x08, 0x50, 0x6c, 0x61, 0x74, 0x66,
	0x6f, 0x72, 0x6d, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6f, 0x63, 0x69, 0x5f,
	0x76, 0x31, 0x2e, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x52, 0x08, 0x50, 0x6c, 0x61,
	0x74, 0x66, 0x6f, 0x72, 0x6d, 0x12, 0x30, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6f, 0x63, 0x69, 0x5f, 0x76, 0x31, 0x2e, 0x49,
	0x6d, 0x61, 0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x48, 0x02, 0x52, 0x06, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x88, 0x01, 0x01, 0x12, 0x2b, 0x0a, 0x06, 0x52, 0x6f, 0x6f, 0x74, 0x46,
	0x53, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x6f, 0x63, 0x69, 0x5f, 0x76, 0x31,
	0x2e, 0x52, 0x6f, 0x6f, 0x74, 0x46, 0x53, 0x48, 0x03, 0x52, 0x06, 0x52, 0x6f, 0x6f, 0x74, 0x46,
	0x53, 0x88, 0x01, 0x01, 0x12, 0x29, 0x0a, 0x07, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x18,
	0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6f, 0x63, 0x69, 0x5f, 0x76, 0x31, 0x2e, 0x48,
	0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x07, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x42,
	0x0a, 0x0a, 0x08, 0x5f, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x09, 0x0a, 0x07, 0x5f,
	0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x42, 0x09, 0x0a, 0x07, 0x5f, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x42, 0x09, 0x0a, 0x07, 0x5f, 0x52, 0x6f, 0x6f, 0x74, 0x46, 0x53, 0x22, 0x93, 0x05, 0x0a,
	0x0b, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x49, 0x0a, 0x0c,
	0x45, 0x78, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x50, 0x6f, 0x72, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x25, 0x2e, 0x6f, 0x63, 0x69, 0x5f, 0x76, 0x31, 0x2e, 0x49, 0x6d, 0x61, 0x67,
	0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x45, 0x78, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x50,
	0x6f, 0x72, 0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0c, 0x45, 0x78, 0x70, 0x6f, 0x73,
	0x65, 0x64, 0x50, 0x6f, 0x72, 0x74, 0x73, 0x12, 0x3a, 0x0a, 0x07, 0x56, 0x6f, 0x6c, 0x75, 0x6d,
	0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x6f, 0x63, 0x69, 0x5f, 0x76,
	0x31, 0x2e, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x56, 0x6f,
	0x6c, 0x75, 0x6d, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x56, 0x6f, 0x6c, 0x75,
	0x6d, 0x65, 0x73, 0x12, 0x37, 0x0a, 0x06, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x03, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x6f, 0x63, 0x69, 0x5f, 0x76, 0x31, 0x2e, 0x49, 0x6d, 0x61,
	0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x12, 0x12, 0x0a, 0x04,
	0x55, 0x73, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x55, 0x73, 0x65, 0x72,
	0x12, 0x10, 0x0a, 0x03, 0x45, 0x6e, 0x76, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x03, 0x45,
	0x6e, 0x76, 0x12, 0x1e, 0x0a, 0x0a, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x43, 0x6d, 0x64, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x03, 0x43, 0x6d, 0x64, 0x12, 0x23, 0x0a, 0x0a, 0x57, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x44,
	0x69, 0x72, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0a, 0x57, 0x6f, 0x72, 0x6b,
	0x69, 0x6e, 0x67, 0x44, 0x69, 0x72, 0x88, 0x01, 0x01, 0x12, 0x23, 0x0a, 0x0a, 0x53, 0x74, 0x6f,
	0x70, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52,
	0x0a, 0x53, 0x74, 0x6f, 0x70, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x88, 0x01, 0x01, 0x12, 0x20,
	0x0a, 0x0b, 0x41, 0x72, 0x67, 0x73, 0x45, 0x73, 0x63, 0x61, 0x70, 0x65, 0x64, 0x18, 0x0a, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0b, 0x41, 0x72, 0x67, 0x73, 0x45, 0x73, 0x63, 0x61, 0x70, 0x65, 0x64,
	0x1a, 0x55, 0x0a, 0x11, 0x45, 0x78, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x50, 0x6f, 0x72, 0x74, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6f, 0x63, 0x69, 0x5f, 0x76, 0x31, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x50, 0x0a, 0x0c, 0x56, 0x6f, 0x6c, 0x75, 0x6d,
	0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6f, 0x63, 0x69, 0x5f, 0x76,
	0x31, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62,
	0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x3a, 0x02, 0x38, 0x01, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x57, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67,
	0x44, 0x69, 0x72, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x53, 0x74, 0x6f, 0x70, 0x53, 0x69, 0x67, 0x6e,
	0x61, 0x6c, 0x22, 0x36, 0x0a, 0x06, 0x52, 0x6f, 0x6f, 0x74, 0x46, 0x53, 0x12, 0x12, 0x0a, 0x04,
	0x54, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x44, 0x69, 0x66, 0x66, 0x49, 0x44, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x07, 0x44, 0x69, 0x66, 0x66, 0x49, 0x44, 0x73, 0x22, 0x88, 0x02, 0x0a, 0x07, 0x48,
	0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x12, 0x39, 0x0a, 0x07, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x48, 0x00, 0x52, 0x07, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x88, 0x01,
	0x01, 0x12, 0x21, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42,
	0x79, 0x88, 0x01, 0x01, 0x12, 0x1b, 0x0a, 0x06, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x48, 0x02, 0x52, 0x06, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x88, 0x01,
	0x01, 0x12, 0x1d, 0x0a, 0x07, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x03, 0x52, 0x07, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x88, 0x01, 0x01,
	0x12, 0x23, 0x0a, 0x0a, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x4c, 0x61, 0x79, 0x65, 0x72, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x08, 0x48, 0x04, 0x52, 0x0a, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x4c, 0x61, 0x79,
	0x65, 0x72, 0x88, 0x01, 0x01, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x64, 0x42, 0x0c, 0x0a, 0x0a, 0x5f, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x79, 0x42,
	0x09, 0x0a, 0x07, 0x5f, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x43,
	0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x45, 0x6d, 0x70, 0x74, 0x79,
	0x4c, 0x61, 0x79, 0x65, 0x72, 0x22, 0x0e, 0x0a, 0x0c, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_oci_config_proto_rawDescOnce sync.Once
	file_oci_config_proto_rawDescData = file_oci_config_proto_rawDesc
)

func file_oci_config_proto_rawDescGZIP() []byte {
	file_oci_config_proto_rawDescOnce.Do(func() {
		file_oci_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_oci_config_proto_rawDescData)
	})
	return file_oci_config_proto_rawDescData
}

var file_oci_config_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_oci_config_proto_goTypes = []interface{}{
	(*Image)(nil),                 // 0: oci_v1.Image
	(*ImageConfig)(nil),           // 1: oci_v1.ImageConfig
	(*RootFS)(nil),                // 2: oci_v1.RootFS
	(*History)(nil),               // 3: oci_v1.History
	(*EmptyMessage)(nil),          // 4: oci_v1.EmptyMessage
	nil,                           // 5: oci_v1.ImageConfig.ExposedPortsEntry
	nil,                           // 6: oci_v1.ImageConfig.VolumesEntry
	nil,                           // 7: oci_v1.ImageConfig.LabelsEntry
	(*timestamppb.Timestamp)(nil), // 8: google.protobuf.Timestamp
	(*Platform)(nil),              // 9: oci_v1.Platform
}
var file_oci_config_proto_depIdxs = []int32{
	8,  // 0: oci_v1.Image.Created:type_name -> google.protobuf.Timestamp
	9,  // 1: oci_v1.Image.Platform:type_name -> oci_v1.Platform
	1,  // 2: oci_v1.Image.Config:type_name -> oci_v1.ImageConfig
	2,  // 3: oci_v1.Image.RootFS:type_name -> oci_v1.RootFS
	3,  // 4: oci_v1.Image.History:type_name -> oci_v1.History
	5,  // 5: oci_v1.ImageConfig.ExposedPorts:type_name -> oci_v1.ImageConfig.ExposedPortsEntry
	6,  // 6: oci_v1.ImageConfig.Volumes:type_name -> oci_v1.ImageConfig.VolumesEntry
	7,  // 7: oci_v1.ImageConfig.Labels:type_name -> oci_v1.ImageConfig.LabelsEntry
	8,  // 8: oci_v1.History.Created:type_name -> google.protobuf.Timestamp
	4,  // 9: oci_v1.ImageConfig.ExposedPortsEntry.value:type_name -> oci_v1.EmptyMessage
	4,  // 10: oci_v1.ImageConfig.VolumesEntry.value:type_name -> oci_v1.EmptyMessage
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_oci_config_proto_init() }
func file_oci_config_proto_init() {
	if File_oci_config_proto != nil {
		return
	}
	file_oci_descriptor_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_oci_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Image); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_oci_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImageConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_oci_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RootFS); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_oci_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*History); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_oci_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EmptyMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_oci_config_proto_msgTypes[0].OneofWrappers = []interface{}{}
	file_oci_config_proto_msgTypes[1].OneofWrappers = []interface{}{}
	file_oci_config_proto_msgTypes[3].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_oci_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_oci_config_proto_goTypes,
		DependencyIndexes: file_oci_config_proto_depIdxs,
		MessageInfos:      file_oci_config_proto_msgTypes,
	}.Build()
	File_oci_config_proto = out.File
	file_oci_config_proto_rawDesc = nil
	file_oci_config_proto_goTypes = nil
	file_oci_config_proto_depIdxs = nil
}
