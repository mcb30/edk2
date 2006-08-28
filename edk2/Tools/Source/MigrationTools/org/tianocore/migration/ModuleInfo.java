/** @file
 
 Copyright (c) 2006, Intel Corporation
 All rights reserved. This program and the accompanying materials
 are licensed and made available under the terms and conditions of the BSD License
 which accompanies this distribution.  The full text of the license may be found at
 http://opensource.org/licenses/bsd-license.php
 
 THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 
 **/
package org.tianocore.migration;

import java.io.*;
import java.util.*;

/*
	Class ModuleInfo is built for scanning the source files, it contains all the needed
information and all the temporary data.
*/
public final class ModuleInfo {
	ModuleInfo(String modulepath) throws Exception {
		this.modulepath = modulepath;
		
		if (MigrationTool.defaultoutput) {
			this.outputpath = this.modulepath.replaceAll(Common.strseparate, "$1");
		} else {
			MigrationTool.ui.println("Choose where to place the result");
			if ((outputpath = MigrationTool.ui.getFilepath("Please choose where to place the output module")) == null) {
				outputpath = modulepath; 
			}
			MigrationTool.ui.println("Output to: " + outputpath);
		}
	}

	public final String modulepath;
	
	public String outputpath = null;
	
	public String modulename = null;
	public String guidvalue = null;
	public String moduletype = null;
	public String entrypoint = null;
	
	public final Set<String> localmodulesources = new HashSet<String>();		//contains both .c and .h
	public final Set<String> preprocessedccodes = new HashSet<String>();
	public final Set<String> msaorinf = new HashSet<String>();				//only a little, hash may be too big for this
	
	public final Set<String> hashfuncc = new HashSet<String>();
	public final Set<String> hashfuncd = new HashSet<String>();
	public final Set<String> hashnonlocalfunc = new HashSet<String>();
	public final Set<String> hashnonlocalmacro = new HashSet<String>();
	public final Set<String> hashEFIcall = new HashSet<String>();
	public final Set<String> hashr8only = new HashSet<String>();
	
	public final Set<String> hashrequiredr9libs = new HashSet<String>();	// hashrequiredr9libs is now all added in SourceFileReplacer 
	public final Set<String> guid = new HashSet<String>();
	public final Set<String> protocol = new HashSet<String>();
	public final Set<String> ppi = new HashSet<String>();

	public final void enroll(String filepath) throws Exception {
		if (filepath.contains(".c") || filepath.contains(".C") || filepath.contains(".h") || 
				filepath.contains(".H") || filepath.contains(".dxs") || filepath.contains(".uni")) {
			localmodulesources.add(filepath.replace(modulepath + "\\", ""));
		} else if (filepath.contains(".inf") || filepath.contains(".msa")) {
			msaorinf.add(filepath.replace(modulepath + "\\", ""));
		}
	}

	public static final boolean isModule(String path) {
		String[] list = new File(path).list();
		for (int i = 0 ; i < list.length ; i++) {
			if (!new File(list[i]).isDirectory()) {
				if (list[i].contains(".inf") || list[i].contains(".msa")) {
					return true;
				}
			}
		}
		return false;
	}
}