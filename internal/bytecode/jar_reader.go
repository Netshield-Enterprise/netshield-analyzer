package bytecode

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// JARAnalyzer analyzes JAR files and extracts bytecode information
type JARAnalyzer struct {
	jarPath string
}

// NewJARAnalyzer creates a new JAR analyzer
func NewJARAnalyzer(jarPath string) *JARAnalyzer {
	return &JARAnalyzer{
		jarPath: jarPath,
	}
}

// ClassFile represents a parsed Java class file
type ClassFile struct {
	ClassName    string
	Methods      []*MethodInfo
	ConstantPool []interface{}
}

// MethodInfo represents a method in a class
type MethodInfo struct {
	Name       string
	Descriptor string
	Code       []byte
	Calls      []MethodCall
}

// MethodCall represents a method invocation
type MethodCall struct {
	ClassName  string
	MethodName string
	Descriptor string
}

// AnalyzeJAR extracts all classes and methods from a JAR file
func (ja *JARAnalyzer) AnalyzeJAR() ([]*ClassFile, error) {
	if ja.jarPath == "" {
		return nil, fmt.Errorf("JAR path is empty")
	}

	// Open the JAR file (which is a ZIP archive)
	reader, err := zip.OpenReader(ja.jarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JAR file: %w", err)
	}
	defer reader.Close()

	var classes []*ClassFile

	// Iterate through files in the JAR
	for _, file := range reader.File {
		// Only process .class files
		if !strings.HasSuffix(file.Name, ".class") {
			continue
		}

		// Skip module-info and package-info classes
		if strings.Contains(file.Name, "module-info") || strings.Contains(file.Name, "package-info") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		// Parse the class file
		classFile, err := ja.parseClassFile(data)
		if err != nil {
			// Skip malformed class files
			continue
		}

		classes = append(classes, classFile)
	}

	return classes, nil
}

// parseClassFile parses a Java class file bytecode
func (ja *JARAnalyzer) parseClassFile(data []byte) (*ClassFile, error) {
	reader := bytes.NewReader(data)

	// Read magic number (0xCAFEBABE)
	var magic uint32
	if err := binary.Read(reader, binary.BigEndian, &magic); err != nil {
		return nil, err
	}
	if magic != 0xCAFEBABE {
		return nil, fmt.Errorf("invalid class file magic number")
	}

	// Read version
	var minor, major uint16
	binary.Read(reader, binary.BigEndian, &minor)
	binary.Read(reader, binary.BigEndian, &major)

	// Parse constant pool
	constantPool, err := ja.parseConstantPool(reader)
	if err != nil {
		return nil, err
	}

	// Read access flags
	var accessFlags uint16
	binary.Read(reader, binary.BigEndian, &accessFlags)

	// Read this class
	var thisClass uint16
	binary.Read(reader, binary.BigEndian, &thisClass)
	className := ja.getClassName(constantPool, int(thisClass))

	// Read super class
	var superClass uint16
	binary.Read(reader, binary.BigEndian, &superClass)

	// Read interfaces
	var interfacesCount uint16
	binary.Read(reader, binary.BigEndian, &interfacesCount)
	for i := 0; i < int(interfacesCount); i++ {
		var iface uint16
		binary.Read(reader, binary.BigEndian, &iface)
	}

	// Read fields
	var fieldsCount uint16
	binary.Read(reader, binary.BigEndian, &fieldsCount)
	for i := 0; i < int(fieldsCount); i++ {
		if err := ja.skipField(reader); err != nil {
			return nil, err
		}
	}

	// Read methods
	var methodsCount uint16
	binary.Read(reader, binary.BigEndian, &methodsCount)

	methods := make([]*MethodInfo, 0)
	for i := 0; i < int(methodsCount); i++ {
		method, err := ja.parseMethod(reader, constantPool)
		if err != nil {
			continue
		}
		methods = append(methods, method)
	}

	return &ClassFile{
		ClassName:    className,
		Methods:      methods,
		ConstantPool: constantPool,
	}, nil
}

// parseConstantPool parses the constant pool from a class file
func (ja *JARAnalyzer) parseConstantPool(reader *bytes.Reader) ([]interface{}, error) {
	var poolCount uint16
	if err := binary.Read(reader, binary.BigEndian, &poolCount); err != nil {
		return nil, err
	}

	pool := make([]interface{}, poolCount)

	for i := 1; i < int(poolCount); i++ {
		var tag uint8
		if err := binary.Read(reader, binary.BigEndian, &tag); err != nil {
			return nil, err
		}

		switch tag {
		case 1: // UTF8
			var length uint16
			binary.Read(reader, binary.BigEndian, &length)
			bytes := make([]byte, length)
			reader.Read(bytes)
			pool[i] = string(bytes)
		case 3: // Integer
			var value int32
			binary.Read(reader, binary.BigEndian, &value)
			pool[i] = value
		case 4: // Float
			var value float32
			binary.Read(reader, binary.BigEndian, &value)
			pool[i] = value
		case 5: // Long
			var value int64
			binary.Read(reader, binary.BigEndian, &value)
			pool[i] = value
			i++ // Long takes 2 slots
		case 6: // Double
			var value float64
			binary.Read(reader, binary.BigEndian, &value)
			pool[i] = value
			i++ // Double takes 2 slots
		case 7: // Class
			var nameIndex uint16
			binary.Read(reader, binary.BigEndian, &nameIndex)
			pool[i] = map[string]uint16{"class": nameIndex}
		case 8: // String
			var stringIndex uint16
			binary.Read(reader, binary.BigEndian, &stringIndex)
			pool[i] = map[string]uint16{"string": stringIndex}
		case 9, 10, 11: // Fieldref, Methodref, InterfaceMethodref
			var classIndex, nameAndTypeIndex uint16
			binary.Read(reader, binary.BigEndian, &classIndex)
			binary.Read(reader, binary.BigEndian, &nameAndTypeIndex)
			pool[i] = map[string]uint16{"class": classIndex, "nameAndType": nameAndTypeIndex}
		case 12: // NameAndType
			var nameIndex, descriptorIndex uint16
			binary.Read(reader, binary.BigEndian, &nameIndex)
			binary.Read(reader, binary.BigEndian, &descriptorIndex)
			pool[i] = map[string]uint16{"name": nameIndex, "descriptor": descriptorIndex}
		case 15: // MethodHandle
			var refKind uint8
			var refIndex uint16
			binary.Read(reader, binary.BigEndian, &refKind)
			binary.Read(reader, binary.BigEndian, &refIndex)
			pool[i] = map[string]interface{}{"kind": refKind, "index": refIndex}
		case 16: // MethodType
			var descriptorIndex uint16
			binary.Read(reader, binary.BigEndian, &descriptorIndex)
			pool[i] = map[string]uint16{"descriptor": descriptorIndex}
		case 18: // InvokeDynamic
			var bootstrapMethodAttrIndex, nameAndTypeIndex uint16
			binary.Read(reader, binary.BigEndian, &bootstrapMethodAttrIndex)
			binary.Read(reader, binary.BigEndian, &nameAndTypeIndex)
			pool[i] = map[string]uint16{"bootstrap": bootstrapMethodAttrIndex, "nameAndType": nameAndTypeIndex}
		default:
			return nil, fmt.Errorf("unknown constant pool tag: %d", tag)
		}
	}

	return pool, nil
}

// parseMethod parses a method from the class file
func (ja *JARAnalyzer) parseMethod(reader *bytes.Reader, constantPool []interface{}) (*MethodInfo, error) {
	var accessFlags uint16
	binary.Read(reader, binary.BigEndian, &accessFlags)

	var nameIndex uint16
	binary.Read(reader, binary.BigEndian, &nameIndex)
	methodName := ja.getString(constantPool, int(nameIndex))

	var descriptorIndex uint16
	binary.Read(reader, binary.BigEndian, &descriptorIndex)
	descriptor := ja.getString(constantPool, int(descriptorIndex))

	method := &MethodInfo{
		Name:       methodName,
		Descriptor: descriptor,
		Calls:      make([]MethodCall, 0),
	}

	// Parse attributes
	var attributesCount uint16
	binary.Read(reader, binary.BigEndian, &attributesCount)

	for i := 0; i < int(attributesCount); i++ {
		var attrNameIndex uint16
		binary.Read(reader, binary.BigEndian, &attrNameIndex)
		attrName := ja.getString(constantPool, int(attrNameIndex))

		var attrLength uint32
		binary.Read(reader, binary.BigEndian, &attrLength)

		attrData := make([]byte, attrLength)
		reader.Read(attrData)

		// Parse Code attribute to extract method calls
		if attrName == "Code" {
			method.Code = attrData
			method.Calls = ja.extractMethodCalls(attrData, constantPool)
		}
	}

	return method, nil
}

// extractMethodCalls extracts method invocations from bytecode
func (ja *JARAnalyzer) extractMethodCalls(code []byte, constantPool []interface{}) []MethodCall {
	calls := make([]MethodCall, 0)

	if len(code) < 8 {
		return calls
	}

	// Skip max_stack and max_locals
	codeReader := bytes.NewReader(code[4:])

	var codeLength uint32
	binary.Read(codeReader, binary.BigEndian, &codeLength)

	bytecode := make([]byte, codeLength)
	codeReader.Read(bytecode)

	// Scan for invoke instructions
	for i := 0; i < len(bytecode); i++ {
		opcode := bytecode[i]

		// Check for invoke instructions
		// 0xB6 = invokevirtual, 0xB7 = invokespecial, 0xB8 = invokestatic, 0xB9 = invokeinterface
		if opcode == 0xB6 || opcode == 0xB7 || opcode == 0xB8 || opcode == 0xB9 {
			if i+2 < len(bytecode) {
				// Read constant pool index
				indexByte1 := bytecode[i+1]
				indexByte2 := bytecode[i+2]
				cpIndex := int(uint16(indexByte1)<<8 | uint16(indexByte2))

				// Extract method reference
				if cpIndex < len(constantPool) {
					call := ja.resolveMethodCall(constantPool, cpIndex)
					if call != nil {
						calls = append(calls, *call)
					}
				}

				// Skip operands
				if opcode == 0xB9 {
					i += 4 // invokeinterface has 2 additional bytes
				} else {
					i += 2
				}
			}
		}
	}

	return calls
}

// resolveMethodCall resolves a method call from the constant pool
func (ja *JARAnalyzer) resolveMethodCall(constantPool []interface{}, index int) *MethodCall {
	if index >= len(constantPool) || constantPool[index] == nil {
		return nil
	}

	methodRef, ok := constantPool[index].(map[string]uint16)
	if !ok {
		return nil
	}

	classIndex := methodRef["class"]
	nameAndTypeIndex := methodRef["nameAndType"]

	className := ja.getClassName(constantPool, int(classIndex))

	if int(nameAndTypeIndex) >= len(constantPool) {
		return nil
	}

	nameAndType, ok := constantPool[nameAndTypeIndex].(map[string]uint16)
	if !ok {
		return nil
	}

	methodName := ja.getString(constantPool, int(nameAndType["name"]))
	descriptor := ja.getString(constantPool, int(nameAndType["descriptor"]))

	return &MethodCall{
		ClassName:  className,
		MethodName: methodName,
		Descriptor: descriptor,
	}
}

// getString retrieves a string from the constant pool
func (ja *JARAnalyzer) getString(pool []interface{}, index int) string {
	if index >= len(pool) || pool[index] == nil {
		return ""
	}
	if str, ok := pool[index].(string); ok {
		return str
	}
	return ""
}

// getClassName retrieves a class name from the constant pool
func (ja *JARAnalyzer) getClassName(pool []interface{}, index int) string {
	if index >= len(pool) || pool[index] == nil {
		return ""
	}

	if classRef, ok := pool[index].(map[string]uint16); ok {
		nameIndex := classRef["class"]
		return ja.getString(pool, int(nameIndex))
	}

	return ""
}

// skipField skips a field entry in the class file
func (ja *JARAnalyzer) skipField(reader *bytes.Reader) error {
	// Skip access_flags, name_index, descriptor_index
	reader.Seek(6, io.SeekCurrent)

	// Read attributes count
	var attributesCount uint16
	binary.Read(reader, binary.BigEndian, &attributesCount)

	// Skip attributes
	for i := 0; i < int(attributesCount); i++ {
		reader.Seek(2, io.SeekCurrent) // attribute_name_index
		var attrLength uint32
		binary.Read(reader, binary.BigEndian, &attrLength)
		reader.Seek(int64(attrLength), io.SeekCurrent)
	}

	return nil
}

// BuildCallGraphFromJAR builds a call graph from a JAR file
func (ja *JARAnalyzer) BuildCallGraphFromJAR() (*models.CallGraph, error) {
	classes, err := ja.AnalyzeJAR()
	if err != nil {
		return nil, err
	}

	cg := models.NewCallGraph()

	// Add all methods as nodes
	for _, class := range classes {
		for _, method := range class.Methods {
			methodID := models.GetMethodID(class.ClassName, method.Name, method.Descriptor)

			node := &models.MethodNode{
				ClassName:  class.ClassName,
				MethodName: method.Name,
				Signature:  method.Descriptor,
				IsExternal: true, // Assume external for now
				Package:    ja.extractPackage(class.ClassName),
			}

			cg.AddNode(methodID, node)

			// Add edges for method calls
			for _, call := range method.Calls {
				calleeID := models.GetMethodID(call.ClassName, call.MethodName, call.Descriptor)
				cg.AddEdge(methodID, calleeID)
			}
		}
	}

	return cg, nil
}

// extractPackage extracts package name from class name
func (ja *JARAnalyzer) extractPackage(className string) string {
	lastSlash := strings.LastIndex(className, "/")
	if lastSlash == -1 {
		return ""
	}
	return strings.ReplaceAll(className[:lastSlash], "/", ".")
}
