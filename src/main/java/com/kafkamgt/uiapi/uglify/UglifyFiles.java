package com.kafkamgt.uiapi.uglify;

import java.io.File;
import java.io.IOException;

public class UglifyFiles {

//    String cssDir = "C:/murali/IdeaProjects/kafkawizepro/src/main/resources/static/assets/css/";
//    String sourceDirJsFiles = "src\\main\\resources\\static\\js\\";

    String sourceDirJsFiles = "./target/classes/static/js/";
    String cssDir = "./target/classes/static/assets/css/";

    // js files
    public UglifyFiles(){
        String osName = System.getProperty("os.name");
        System.out.println("OS : "+osName);
        Runtime rt = Runtime.getRuntime();

        uglifyJsFiles(osName, rt);
        uglifyCssFiles(osName, rt);
    }

    private void uglifyCssFiles(String osName, Runtime rt){
        String styleCssFile = cssDir + "style.css";
        String styleBlueDarkCssFile = cssDir + "colors/blue-dark.css";

        String commandToExec = "uglifycss " + styleCssFile + " --output " + styleCssFile;
        executeCommand(rt, commandToExec, osName);

        commandToExec = "uglifycss " + styleBlueDarkCssFile + " --output " + styleBlueDarkCssFile;
        executeCommand(rt, commandToExec, osName);
    }

    private void uglifyJsFiles(String osName, Runtime rt) {

        File f =new File(sourceDirJsFiles);
        File[] filesInDir = f.listFiles();
        if (filesInDir != null) {

            for (File file : filesInDir) {
                String commandToExec = "uglifyjs " + file.getAbsolutePath() + " -o " + file.getAbsolutePath();
                executeCommand(rt, commandToExec, osName);
            }
        }
    }

    private void executeCommand(Runtime rt, String commandToExec, String osName) {
        String commandPrefix = "";

        if(osName.startsWith("Windows"))
            commandPrefix = "cmd.exe /c ";
        else
            commandPrefix = "";

        commandToExec = commandPrefix + commandToExec;

        System.out.println(commandToExec);
        try {
            rt.exec(commandToExec);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new UglifyFiles();
    }
}
