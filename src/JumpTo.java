//? name=JumpTo , shortcut=Ctrl+Shift+J, help=From manifest view jump to the corresponding code

import jeb.api.IScript;
import jeb.api.JebInstance;
import jeb.api.ui.*;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class JumpTo implements IScript {

    @Override
    public void run(JebInstance jebInstance) {
        JebUI ui = jebInstance.getUI();
        ui.focusView(View.Type.MANIFEST);
        XmlView mfView = (XmlView) ui.getView(View.Type.MANIFEST);

        if (mfView == null) {
            jebInstance.print("Not AndroidManifest.xml!");
            return;
        }

        String text = mfView.getText();

        String sig = mfView.getActiveItem();
        if (sig == null) {
            jebInstance.print("Error : could not get the active item.");
            return;
        }

        // get package
        String pkg = null;
        String pattern = "package=\"[^\"]*\"";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(text);
        if (m.find()) {
            pkg = m.group(0).split("\"")[1];
        }

        if (sig.startsWith(".")) {
            if (pkg == null) {
                jebInstance.print("package is null !!");
                return;
            }
            sig = pkg + sig;
        }

        AssemblyView assemblyView = (AssemblyView) ui.getView(View.Type.ASSEMBLY);
        if (assemblyView == null) {
            jebInstance.print("No Assembly view");
            return;
        }

        String smaliFormat = 'L' + sig.replace('.', '/') + ";";
        jebInstance.print(smaliFormat);
        if (!assemblyView.setCodePosition(new CodePosition(smaliFormat))) {
            jebInstance.print(smaliFormat + " not found in the dex file, maybe it's in the sub file.");
            return;
        }

        ui.focusView(View.Type.ASSEMBLY);
    }
}
