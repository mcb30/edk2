/** @file
 SplitfileTask class.

 SplitfileTask is used to call splitfile.exe to split input file to 2 output
 file.


 Copyright (c) 2006, Intel Corporation
 All rights reserved. This program and the accompanying materials
 are licensed and made available under the terms and conditions of the BSD License
 which accompanies this distribution.  The full text of the license may be found at
 http://opensource.org/licenses/bsd-license.php

 THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

 **/
package org.tianocore.framework.tasks;

import java.io.File;

import org.apache.tools.ant.Task;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.taskdefs.Execute;
import org.apache.tools.ant.taskdefs.LogStreamHandler;
import org.apache.tools.ant.types.Commandline;

import org.tianocore.common.logger.EdkLog;

/**
  SplitfileTask class.

  SplitfileTask is used to call splitfile.exe to split input file to 2 output
  file.
**/
public class SplitfileTask extends Task implements EfiDefine {
    //
    // Tool name
    // 
    private static String toolName = "SplitFile";

    //
    // input file
    //
    private FileArg inputFile = new FileArg();

    //
    // offset value
    //
    private ToolArg offset = new ToolArg();

    //
    // Output directory
    // 
    private String outputDir = ".";

    /**
      execute
     
      SplitfleTask execute function is to assemble tool command line & execute
      tool command line
     
      @throws BuidException
     **/
    public void execute() throws BuildException {

        Project project = this.getOwningTarget().getProject();

        //
        // absolute path of efi tools
        //
        String path = project.getProperty("env.FRAMEWORK_TOOLS_PATH");
        String command;
        String argument;
        if (path == null) {
            command = toolName;
        } else {
            command = path + File.separator + toolName;
        }

        //
        // argument of tools
        //
        argument = "" + inputFile + offset;

        //
        // return value of fwimage execution
        //
        int revl = -1;

        try {
            Commandline cmdline = new Commandline();
            cmdline.setExecutable(command);
            cmdline.createArgument().setLine(argument);

            LogStreamHandler streamHandler = new LogStreamHandler(this,
                    Project.MSG_INFO, Project.MSG_WARN);
            Execute runner = new Execute(streamHandler, null);

            runner.setAntRun(project);
            runner.setCommandline(cmdline.getCommandline());
            runner.setWorkingDirectory(new File(outputDir));

            EdkLog.log(this, EdkLog.EDK_VERBOSE, Commandline.toString(cmdline.getCommandline()));
            String fileName = inputFile.toFileList();
            EdkLog.log(this, EdkLog.EDK_INFO, fileName + " => " + fileName + "1 " + fileName + "2");

            revl = runner.execute();
            if (EFI_SUCCESS == revl) {
                //
                // command execution success
                //
                EdkLog.log(this, EdkLog.EDK_VERBOSE, toolName + " succeeded!");
            } else {
                //
                // command execution fail
                //
                EdkLog.log(this, EdkLog.EDK_INFO, "ERROR = " + Integer.toHexString(revl));
                throw new BuildException(toolName + " failed!");
            }
        } catch (Exception e) {
            throw new BuildException(e.getMessage());
        }
    }

    /**
      getInputFile
     
      This function is to get class member "inputFile".
     
      @return string of input file name.
     **/
    public String getInputFile() {
        return inputFile.getValue();
    }

    /**
      setComponentType
     
      This function is to set class member "inputFile".
     
      @param inputFile
                 string of input file name.
     **/
    public void setInputFile(String inputFile) {
        this.inputFile.setArg(" ", inputFile);
    }

    /**
      getOffset

      This function is to get class member "offset"

      @return offset value of string.
    **/
    public String getOffset() {
        return offset.getValue();
    }

    /**
      setOffset

      This function is to set class member "offset"

      @param offset
                 string of offset value.
    **/
    public void setOffset(String offset) {
        this.offset.setArg(" ", offset);
    }

    /**
      getOutputDir
     
      This function is to get class member "outputDir"
     
      @return outputDir string of output directory.
     **/
    public String getOutputDir() {
        return outputDir;
    }

    /**
      setOutputDir
     
      This function is to set class member "outputDir"
     
      @param outputDir
                 string of output directory.
     **/
    public void setOutputDir(String outputDir) {
        this.outputDir = outputDir;
    }
}
