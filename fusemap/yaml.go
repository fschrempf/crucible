// crucible
// One-Time-Programmable (OTP) fusing tool
//
// Copyright (c) WithSecure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package fusemap

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/ghodss/yaml"
)

// Parse converts a fusemap YAML payload to a FuseMap structure.
func Parse(y []byte) (fusemap *FuseMap, err error) {
	fusemap = &FuseMap{}
	err = yaml.Unmarshal(y, fusemap)

	if err != nil {
		return
	}

	err = fusemap.Validate()

	return
}

// Find searches a fusemap YAML file for a given processor and reference manual
// identifier within a directory. The YAML file is parsed, validated and
// converted to a FuseMap structure.
func Find(dir fs.FS, processor string, reference string) (fusemap *FuseMap, err error) {
	path := processor + ".yaml"

	y, err := fs.ReadFile(dir, path)

	if err != nil {
		return
	}

	fusemap, err = Parse(y)

	if err != nil {
		return
	}

	if processor != fusemap.Processor {
		err = fmt.Errorf("fusemap file name must match its processor parameter (%s != %s)",
			processor, fusemap.Processor)
	}

	if reference != fusemap.Reference {
		err = fmt.Errorf("invalid reference")
	}

	return
}

// Open parses a fusemap YAML file, validates it and converts it to a FuseMap
// structure.
func Open(path string) (fusemap *FuseMap, err error) {
	y, err := os.ReadFile(path)

	if err != nil {
		return
	}

	return Parse(y)
}
