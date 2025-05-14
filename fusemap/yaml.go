// crucible
// One-Time-Programmable (OTP) fusing tool
//
// Copyright (c) WithSecure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package fusemap

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/ghodss/yaml"
	"dario.cat/mergo"
)

// Find searches a fusemap YAML file for a given processor and reference manual
// identifier within a directory. The YAML file is parsed, validated and
// converted to a FuseMap structure.
func Find(dir fs.FS, processor string, reference string) (fusemap *FuseMap, err error) {
	path := processor + ".yaml"

	y, err := fs.ReadFile(dir, path)

	if err != nil {
		return
	}

	path = processor + ".override.yaml"

	o, err := fs.ReadFile(dir, path)

	if err != nil  && !errors.Is(err, fs.ErrNotExist) {
		return
	}

	fusemap, err = Parse(y, o)

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

// Parse converts a fusemap YAML payload to a FuseMap structure.
func Parse(y []byte, o []byte) (fusemap *FuseMap, err error) {
	fusemap = &FuseMap{}
	override := FuseMap{}
	err = yaml.Unmarshal(y, fusemap)

	if err != nil {
		return
	}

	if o != nil {
		err = yaml.Unmarshal(o, &override)

		if err != nil {
			return
		}

		err = mergo.Merge(&override, fusemap)

		if err != nil {
			return
		}

		*fusemap = override
	}

	err = fusemap.Validate()

	return
}
