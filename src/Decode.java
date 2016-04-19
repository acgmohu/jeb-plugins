//? name=Decode , shortcut=Ctrl+Shift+D, help=Decode

import jeb.api.IScript;
import jeb.api.JebInstance;
import jeb.api.ast.*;
import jeb.api.dex.Dex;
import jeb.api.dex.DexField;
import jeb.api.dex.DexMethod;
import jeb.api.ui.JavaView;
import jeb.api.ui.JebUI;
import jeb.api.ui.View;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.lang.Class;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;
import java.util.*;


public class Decode implements IScript {

    public static JebInstance jeb;
    /**
     * 类名过滤列表
     */
    static ArrayList<String> filterTargetClassList;
    static HashMap<String, Constant> staticFieldMap;
    static HashMap<String, IElement> staticAssignmentMap;
    static String currentStaticFieldSig;
    static ArrayList<String> supportTypes;
    static ArrayList<String> supportArgs;
    //    static ArrayList<String> supportReturns;
    static boolean isDecompileAllClasses = false;
    /**
     * 内部静态方法列表
     */
    static ArrayList<String> staticInternalMethodList;
    /**
     * 静态自定义方法列表
     */
    static ArrayList<String> staticCustomMethodList;
    /**
     * 手工解密方法映射，Key为jar中的解密方法，Value为自己重写的解密方法。 <p />
     * 最好使用decode0()，
     * "La/p/k/class;->decode":myDecode
     */
    static HashMap<String, String> decryptMethodMap;
    /**
     * 表示是否手工解密，默认为false。 <br />
     * 执行手工解密的时候，自动设为true，解密完毕后，会还原默认值。
     */
    static boolean isManual = false;
    static Class aClass;
    /**
     * 当前正在解密的方法
     */
    static String currentMethodSig;
    static String argsName;
    static Class<?>[] args;
    static HashMap<String, Object> localVariableMap;

    static ArrayList<String> filterDecodeMethodList;

    static {
        staticFieldMap = new HashMap<String, Constant>();
        localVariableMap = new HashMap<String, Object>();
        staticAssignmentMap = new HashMap<String, IElement>();
        staticInternalMethodList = new ArrayList<String>();
        staticInternalMethodList.add("Ljava/lang/String;-><init>([B)V");

        supportArgs = new ArrayList<String>();
        // 支持无参解密
        supportArgs.add("");
//        支持一个参数
        supportArgs.add("I");
        supportArgs.add("B");
        supportArgs.add("I");
        supportArgs.add("J");
        supportArgs.add("F");
        supportArgs.add("D");
        supportArgs.add("C");
        supportArgs.add("Ljava/lang/String;");
        // 支持数组类解密函数
        supportArgs.add("[B");
        supportArgs.add("[I");
        supportArgs.add("[J");
        supportArgs.add("[F");
        supportArgs.add("[D");
        supportArgs.add("[C");
        supportArgs.add("[Ljava/lang/String;");
        // 支持多个参数
        supportArgs.add("II");
        supportArgs.add("III");

        supportArgs.add("Ljava/lang/String;Ljava/lang/String;");


        supportTypes = new ArrayList<String>();
        supportTypes.add("I");
        supportTypes.add("Ljava/lang/String;");
        supportTypes.add("[B");

        staticCustomMethodList = new ArrayList<String>();

        filterDecodeMethodList = new ArrayList<String>(); // 解密方法解过滤，仅仅反射符合条件的方法，如果为空，则全部反射
//        filterDecodeMethodList.add("tt/e/g;->a([C)");
        filterTargetClassList = new ArrayList<String>(); // 需要解密的类，仅仅解密这些类，如果为空，则尝试解密所有的泪
//        filterTargetClassList.add("e/b;");


        // 如果统一为myDecode的话，假如有2个myDecode方法呢？只要参数不一样，都可以直接映射。
        decryptMethodMap = new HashMap<String, String>();
//        decryptMethodMap.put("Lcom/uu/o/StringEncode;->decode(Ljava/lang/String;)Ljava/lang/String;", "myDecode");
//        decryptMethodMap.put("Lcom/android/mtp/rp/MyReceiver;->a([B)Ljava/lang/String;", "myDecode");
//        decryptMethodMap.put("Lcom/android/mtp/rp/MyService;->a([B)Ljava/lang/String;", "myDecode");
//        decryptMethodMap.put("Lcom/android/mtp/rp/c;->a([B)Ljava/lang/String;", "myDecode");
//        decryptMethodMap.put("Lcom/google/rp/confirm/MyService;->a([B)Ljava/lang/String;", "myDecode");
//        decryptMethodMap.put("Lcom/google/rp/confirm/c;->a([B)Ljava/lang/String;", "myDecode");
//        decryptMethodMap.put("Lcom/emgp/wfm/b;->a(Ljava/lang/String;)Ljava/lang/String;", "myDecode");


    }

    Constant.Builder cstBuilder;
    ReflectInvoke reflectInvoke;
    Dex dex;
    JavaView javaView;

    public static byte[] decode2(String arg4, byte[] arg5, String arg6) {
        byte[] v0_2;
        try {
            SecretKey v0_1 = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(arg4.
                    getBytes()));
            Cipher v1 = Cipher.getInstance("DES/CBC/PKCS5Padding");
            v1.init(2, ((Key) v0_1), new IvParameterSpec(arg6.getBytes()));
            v0_2 = v1.doFinal(arg5);
        } catch (Exception v0) {
            v0.printStackTrace();
            v0_2 = null;
        }

        return v0_2;
    }


//  ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓ 以下是手工解密函数 ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓

//    public byte[] myDecode(String value) {
//        return null;
//    }

    public static String myDecode(String value) {
        int index;
        byte[] valueArr;
        int[] intArr;
        String result = null;
        try {
            intArr = new int[]{102, 201, 233, 40, 18, 58, 10, 250, 42, 26, 98, 152, 135, 64, 48, 111};
            if (value == null) {
                return result;
            }

            valueArr = value.getBytes("UTF-8");
            index = 0;
            while (index < valueArr.length) {
                for (int i = 0; i < intArr.length; ++i) {
                    valueArr[index] = ((byte) (valueArr[index] ^ intArr[i]));
                }

                ++index;
            }

            result = new String(valueArr, "UTF-8");

        } catch (UnsupportedEncodingException v2) {
            return null;
        }

        return result;
    }

    public String myDecode() {
        return null;
    }

    public String myDecode(int i) {
        return null;
    }

    public String myDecode(int a, int b) {
        return null;
    }

    public String myDecode(int a, int b, int c) {
        return null;
    }

    public String myDecode(String s1, String s2) {
        return null;
    }

    public String myDecode(byte[] arg1) {
        String v0 = arg1 == null ? "" : new String(arg1);
        return v0;
    }

    private String myDecode(int[] intArr) {
        return null;
    }

    private String myDecode(float[] floats) {
        return null;
    }

    private String myDecode(double[] doubles) {
        return null;
    }

    private String myDecode(char[] chars) {
        return null;
    }

    private String myDecode(String[] strs) {
        return null;
    }

    private String myDecode(short[] shorts) {
        return null;
    }

    private String myDecode(long[] longs) {
        return null;
    }

    @Override
    public void run(JebInstance jebInstance) {
        jeb = jebInstance;
        JebUI ui = jebInstance.getUI();
        javaView = (JavaView) ui.getView(View.Type.JAVA);
        dex = jebInstance.getDex();
        cstBuilder = new Constant.Builder(jebInstance);

//        jeb.print(System.getProperty("java.ext.dirs"));

        new Thread() {
            public void run() {
                boolean flag = true;
                while (flag) {

                    System.out.println("1. Auto Decode Static Field.");
                    System.out.println("2. Auto Decode Static Internal Method.");
                    System.out.println("3. Auto Decode Static Custom Method.");
                    System.out.println("4. Manually Decode Custom Method.");
                    System.out.println("6. Set decode method filter.");
                    System.out.println("7. Set target classes filter.");
                    System.out.println("8. Show Filters.");
                    System.out.println("9. Clear Filters.");
                    System.out.println("0. Exit");

                    Scanner scanner = new Scanner(System.in);
                    System.out.print("Select : ");
                    String str = scanner.nextLine();

                    if (str.equals("1")) {
                        decompileAllClass();
                        initStaticFieldMap();
                        autoDecodeStaticField();
                    } else if (str.equals("2")) {
                        decompileAllClass();
                        autoDecodeStaticInternalMethod();
                    } else if (str.equals("3")) {
                        decompileAllClass();
                        autoDecodeStaticCustomMethod();
                    } else if (str.equals("4")) {
                        isManual = true;
                        decompileAllClass();
                        decodeCustomMethod();
                        isManual = false;
                    } else if (str.equals("6")) {
                        Scanner scanner2 = new Scanner(System.in);
                        System.out.print("Decode method filter(p1/p2/ or p2/c0;->m1) : ");
                        String filterWord = scanner2.nextLine();
                        filterDecodeMethodList.add(filterWord);
                    } else if (str.equals("7")) {
                        Scanner scanner2 = new Scanner(System.in);
                        System.out.print("Target classes filter(Lp or Lp1/p2/class) : ");
                        String filterWord = scanner2.nextLine();
                        filterTargetClassList.add(filterWord);
                    } else if (str.equals("8")) {
                        System.out.println("Decode Methods:");
                        for (String s : filterDecodeMethodList) {
                            System.out.println(s);
                        }

                        System.out.println("Target Classes:");
                        for (String s : filterTargetClassList) {
                            System.out.println(s);
                        }
                    } else if (str.equals("9")) {
                        filterDecodeMethodList.clear();
                        filterTargetClassList.clear();
                        isDecompileAllClasses = false;
                    } else if (str.equals("0")) {
                        System.out.println("--------------- EXIT THE SCRIPT. ---------------");
                        flag = false;
                    }

                    System.out.println();
                    javaView.refresh();

                }

            }
        }.start();


    }


// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑ 以上是手工解密函数 ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


    private void decompileAllClass() {
        if (isDecompileAllClasses) {
            return;
        }

        List classSignatures = dex.getClassSignatures(true);
        for (Object obj : classSignatures) {
            String sig = (String) obj;
            if (filterTargetClassList.size() < 1) {
                jeb.decompileClass(sig);
                continue;
            }

            if (!filterTargetClasses(sig)) {
                jeb.decompileClass(sig);
            } else if (!filterDecodeMethod(sig)) {
                jeb.decompileClass(sig);
            }
        }

        isDecompileAllClasses = true;
    }

    private void autoDecodeStaticCustomMethod() {
        initStaticAssignmentMap();
        initStaticMethodList();
        processStaticCustomMethods(staticCustomMethodList);

        staticCustomMethodList.clear();
    }


    /**
     * 将支持的静态自定义方法（返回值为字符串和B数组），初始化到 staticCustomMethodList 中
     *
     *
     */
    private void initStaticMethodList() {
        List classSignatures = dex.getClassSignatures(true);
        for (Object obj : classSignatures) {
            String classSig = (String) obj;

            jeb.api.ast.Class decompiledClassTree = jeb.getDecompiledClassTree(classSig);
            if (decompiledClassTree == null) {
                continue;
            }

            List methods = decompiledClassTree.getMethods();
            for (Object o : methods) {
                jeb.api.ast.Method method = (jeb.api.ast.Method) o;
                String methodSignature = method.getSignature();

                if (filterDecodeMethod(methodSignature)) {
                    continue;
                }

                if (method.isStatic()) {
                    if (methodSignature.endsWith(")Ljava/lang/String;")) {
                        String argsName = getArgsName(methodSignature);
                        if (supportArgs.contains(argsName)) {
                            Class aClass = findClass(getClassSig(methodSignature));
                            if (aClass != null) {
                                staticCustomMethodList.add(methodSignature);
                            }
                        }
                    } else if (methodSignature.endsWith("Ljava/lang/String;)[B")) {
                        String argsName = getArgsName(methodSignature);
                        if (supportArgs.contains(argsName)) {
                            Class aClass = findClass(getClassSig(methodSignature));
                            if (aClass != null) {
                                staticCustomMethodList.add(methodSignature);
                            }
                        }
                    }
                }
            }
        }
    }


    /**
     * 调用lig/*.jar包的解密方法解密。
     *
     * 初始化自定义解密方法
     */
    private void processStaticCustomMethods(ArrayList<String> customMethodList) {
        for (String methodSig : customMethodList) {
            currentMethodSig = methodSig;
            String className = getClassSig(methodSig);

            aClass = findClass(className);
            if (aClass == null) {
                continue;
            }

            String methodFullName = getMethodName(methodSig);
            args = getArgs(methodSig);
            if (args == null) {
                continue;
            }

            // 将静态解密方法，反射调用
            reflectInvoke = new ReflectInvoke(methodFullName, args);

            // 查找该方法，并进行解密
            processStaticCustomMethod();
        }
    }

    private void autoDecodeStaticInternalMethod() {
        for (String methodSig : staticInternalMethodList) {
            currentMethodSig = methodSig;

            int methodCount = dex.getMethodCount();
            for (int i = 0; i < methodCount; i++) {
                DexMethod method = dex.getMethod(i);
                if (method.getSignature(true).equals(currentMethodSig)) {
                    List methodReferences = dex.getMethodReferences(method.getIndex());
                    HashSet<Object> methodRefIdxSet = new HashSet<Object>(methodReferences);
                    for (Object obj : methodRefIdxSet) {
                        int refIdx = (Integer) obj;
                        DexMethod refMethod = dex.getMethod(refIdx);
                        String refMethodSignature = refMethod.getSignature(true);

                        if (filterTargetClasses(refMethodSignature)) {
                            continue;
                        }

                        jeb.api.ast.Method decompiledMethodTree = jeb.getDecompiledMethodTree(refMethodSignature);
                        if (decompiledMethodTree == null) {
                            continue;
                        }

                        Block block = decompiledMethodTree.getBody();
                        processBlock(block);
                    }
                    break;
                }
            }
        }
    }

    /**
     * 在初始化解密函数的时候使用；如果可过滤，返回true。
     *
     * @param sig
     * @return
     */
    private boolean filterDecodeMethod(String sig) {
        if (filterDecodeMethodList.size() == 0) {
            return false;
        }

        for (String filter : filterDecodeMethodList) {
            if (sig.contains(filter)) {
                return false;
            }

            if (!sig.contains(";->") && filter.contains(";->")) {
                if (sig.contains(filter.split("->")[0])) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * 在开始解密的时候使用，可忽略/不解密的类，返回true
     * @param sig
     * @return
     */
    private boolean filterTargetClasses(String sig) {
        if (filterTargetClassList.size() == 0) {
            return false;
        }

        for (String filter : filterTargetClassList) {
            if (sig.contains(filter)) {
                return false;
            }
        }

        return true;
    }

    private void autoDecodeStaticField() {
        int fieldCount = dex.getFieldCount();
        for (int i = 0; i < fieldCount; i++) {
            DexField dexField = dex.getField(i);
            String fieldSig = dexField.getSignature(true);
            if (staticFieldMap.keySet().contains(fieldSig)) {
                currentStaticFieldSig = fieldSig;
                List fieldReferences = dex.getFieldReferences(i);

                HashSet<Object> fieldRefIdxSet = new HashSet<Object>(fieldReferences);
                for (Object obj : fieldRefIdxSet) {
                    int refIdx = (Integer) obj;
                    DexMethod refDexMethod = dex.getMethod(refIdx);
                    String signature = refDexMethod.getSignature(true);

                    if (filterTargetClasses(signature)) {
                        continue;
                    }

                    jeb.api.ast.Method decompiledMethodTree = jeb.getDecompiledMethodTree(signature);
                    if (decompiledMethodTree == null) {
                        return;
                    }

                    Block block = decompiledMethodTree.getBody();
                    processBlock(block);
                }
            }

        }
    }

    /**
     * 这里将类型为字符串，且内容为恒变量的静态变量先初始化到一个MAP中。 <br />
     * <br />
     * 如：<br />
     * String str = "I'm a String.";
     * <p/>
     * 用来做替换用的。
     */
    private void initStaticFieldMap() {
        staticFieldMap.clear();

        List classSignatures = dex.getClassSignatures(true);
        for (Object obj : classSignatures) {
            String classSig = (String) obj;

            if (filterTargetClasses(classSig)) {
                continue;
            }

            jeb.decompileClass(classSig);

            jeb.api.ast.Class decompiledClassTree = jeb.getDecompiledClassTree(classSig);

            List methods = decompiledClassTree.getMethods();
            for (Object o : methods) {
                jeb.api.ast.Method method = (jeb.api.ast.Method) o;
                String methodSignature = method.getSignature();

                if (methodSignature.contains("<clinit>()V")) {
                    jeb.api.ast.Method decompiledMethodTree = jeb.getDecompiledMethodTree(methodSignature);
                    if (decompiledMethodTree == null) {
                        continue;
                    }

                    Block block = decompiledMethodTree.getBody();
                    int size = block.size();
                    for (int j = 0; j < size; j++) {
                        Statement statement = block.get(j);
                        if (statement instanceof Assignment) {
                            Assignment assignment = (Assignment) statement;
                            ILeftExpression left = assignment.getLeft();
                            if (left instanceof StaticField) {
                                StaticField staticField = (StaticField) left;
                                String signature = staticField.getField().getSignature();

                                IExpression right = assignment.getRight();
                                if (right instanceof Constant) {
                                    Constant constant = (Constant) right;
                                    String type = constant.getType();
                                    if (type != null && type.equals("Ljava/lang/String;")) {
                                        staticFieldMap.put(signature, cstBuilder.buildString(constant.getString()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

//        for (String key : staticFieldMap.keySet()) {
//            log2cmd(key + " : " + staticFieldMap.get(key).getString());
//        }
    }


    /**
     * 初始化要解密的静态成员变量
     */
    private void initStaticAssignmentMap() {
        staticAssignmentMap.clear();

        List classSignatures = dex.getClassSignatures(true);
        for (Object obj : classSignatures) {
            String classSig = (String) obj;

            if (filterTargetClasses(classSig)) {
                continue;
            }

            jeb.api.ast.Class decompiledClassTree = null;
            try {
                decompiledClassTree = jeb.getDecompiledClassTree(classSig);
            } catch (RuntimeException e) {
                System.out.println("Could not init this class : " + classSig);
                System.out.println("If the classSig has decode method, you can try modify the dex file.");
            }


            if (decompiledClassTree == null) {
                continue;
            }

            List methods = decompiledClassTree.getMethods();
            for (Object o : methods) {
                jeb.api.ast.Method method = (jeb.api.ast.Method) o;
                String methodSignature = method.getSignature();

                if (methodSignature.contains("<clinit>()V")) {
                    jeb.api.ast.Method decompiledMethodTree = jeb.getDecompiledMethodTree(methodSignature);
                    if (decompiledMethodTree == null) {
                        continue;
                    }

                    Block block = decompiledMethodTree.getBody();
                    int size = block.size();
                    for (int j = 0; j < size; j++) {
                        Statement statement = block.get(j);
                        if (statement instanceof Assignment) {
                            Assignment assignment = (Assignment) statement;
                            ILeftExpression left = assignment.getLeft();
                            if (left instanceof StaticField) {
                                StaticField staticField = (StaticField) left;
                                String signature = staticField.getField().getSignature();
                                staticAssignmentMap.put(signature, assignment);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * 调用lib/*.jar包的解密方法解密。
     *
     * 手工解密
     */
    private void decodeCustomMethod() {
        isManual = true;
        for (String methodSig : decryptMethodMap.keySet()) {
            currentMethodSig = methodSig;
            argsName = getArgsName(currentMethodSig);
            processStaticCustomMethod();
        }

        isManual = false;
    }

    // TODO 按照类来遍历
    private void processStaticCustomMethod() {
        int methodCount = dex.getMethodCount();
        for (int i = 0; i < methodCount; i++) {
            DexMethod method = dex.getMethod(i);
            if (method.getSignature(true).equals(currentMethodSig)) {
                List methodReferences = dex.getMethodReferences(method.getIndex());
                if (methodReferences == null) {
                    continue;
                }
                HashSet<Object> methodRefIdxSet = new HashSet<Object>(methodReferences);
                for (Object obj : methodRefIdxSet) {
                    int refIdx = (Integer) obj;
                    DexMethod refMethod = dex.getMethod(refIdx);
                    String refMethodSignature = refMethod.getSignature(true);

                    if (filterTargetClasses(refMethodSignature)) {
                        continue;
                    }

                    jeb.api.ast.Method decompiledMethodTree = jeb.getDecompiledMethodTree(refMethodSignature);
                    if (decompiledMethodTree == null) {
                        continue;
                    }

                    // 拿到语句块（包含语句），遍历所有语句，并处理所有的语句
                    Block block = decompiledMethodTree.getBody();
                    processBlock(block);
                }
                break;
            }
        }
    }

    /**
     * 处理语句块
     *
     * @param block
     */
    private void processBlock(Block block) {
        int size = block.size();
        for (int j = 0; j < size; j++) {
            Statement statement = block.get(j);
            processIElement(statement, statement);
        }

        localVariableMap.clear();
    }

    /**
     * 判断当前语句的类型，跟进行对应的处理
     *
     * @param parentElement
     * @param subElement
     */
    private void processIElement(IElement parentElement, IElement subElement) {
        if (subElement instanceof Assignment) {
            processAssignment(subElement);
        } else if (subElement instanceof Call) {
            processCall(parentElement, subElement);
        } else if (subElement instanceof IfStm) {
            processIfStm(subElement);
        } else if (subElement instanceof WhileStm) {
            processWhileStm(subElement);
        } else if (subElement instanceof TryStm) {
            processTryStm(subElement);
        } else if (subElement instanceof Return) {
            processReturn(subElement);
        } else if (subElement instanceof SwitchStm) {
            processSwitchStm(subElement);
        } else if (subElement instanceof New) {
            processNew(parentElement, subElement);
        } else if (subElement instanceof StaticField) {
            processStaticField(parentElement, subElement);
        } else if (subElement instanceof ForStm) {
            processForStm(subElement);
        } else if (subElement instanceof Constant) {
            // Constant 保存的是boolean, byte, char, short, int, long, float, double　或　string，不需要处理。
        } else if (subElement instanceof Monitor) {
            // Monitor 语句是没办法解析的那种，不处理。
        } else if (subElement instanceof Goto) {
            // Goto 跳转语句，也不处理
        } else if (subElement instanceof Identifier) {
            processIdentifier(subElement);
        } else if (subElement instanceof Throw) {
            processThrow(subElement);
        } else if (subElement instanceof Label) {
            // 无需处理
        } else if (subElement instanceof InstanceField) {
            processInstanceField(subElement);
        } else if (subElement instanceof Expression) {
            processExpression((Expression) subElement);
        } else if (subElement instanceof Definition) {
            processDefinition(subElement);
        } else if (subElement instanceof ConditionalExpression) {
            processConditionalExpression(subElement);
        } else if (subElement instanceof NewArray) {
            processNewArray(subElement);
        } else if (subElement instanceof ArrayElt) {
            // 数组元素，无需处理
        } else if (subElement instanceof Break) {
            // 无需处理
        } else if (subElement instanceof Continue) {
            // 无需处理
        } else if (subElement instanceof DoWhileStm) {
            processDoWhileStm(subElement);
        } else if (subElement instanceof jeb.api.ast.Method) {

            processMethod(subElement);
        } else if (subElement instanceof TypeReference) {
            // TODO
        } else if (subElement instanceof jeb.api.ast.Field) {
            // TODO
        } else {
            System.out.println("IElement : " + subElement.toString());
        }
    }

    /**
     * 处理条件表达式 A ? B : C
     *
     * @param subElement
     */
    private void processConditionalExpression(IElement subElement) {
        ConditionalExpression expression = (ConditionalExpression) subElement;

        IExpression expressionLeft = expression.getLeft();
        processSubElements(expressionLeft, expressionLeft.getSubElements());

        IExpression right0 = expression.getRight0();
        processSubElements(right0, right0.getSubElements());

        IExpression right1 = expression.getRight1();
        processSubElements(right1, right1.getSubElements());
    }

    private void processDoWhileStm(IElement subElement) {
        DoWhileStm doWhileStm = (DoWhileStm) subElement;

        Predicate predicate = doWhileStm.getPredicate();
        processPredicate(predicate);

        Block body = doWhileStm.getBody();
        processBlock(body);
    }

    /**
     * 处理语句的子元素
     *
     * @param parent
     * @param subElements
     */
    private void processSubElements(IElement parent, List subElements) {
        for (Object object : subElements) {
            IElement iElement = (IElement) object;
            processIElement(parent, iElement);
        }
    }

    private void processThrow(IElement subElement) {
        Throw aThrow = (Throw) subElement;
        processSubElements(aThrow, aThrow.getExpression().getSubElements());
    }

    /**
     * 处理非静态变量
     *
     * @param subElement
     */
    private void processInstanceField(IElement subElement) {
        InstanceField instanceField = (InstanceField) subElement;

        processSubElements(instanceField, instanceField.getInstance().getSubElements());
    }

    // 变量
    private void processIdentifier(IElement subElement) {
        Identifier identifier = (Identifier) subElement;
        processSubElements(identifier, identifier.getSubElements());

    }

    private void processForStm(IElement subElement) {
        ForStm forStm = (ForStm) subElement;
        Block body = forStm.getBody();
        processBlock(body);
    }

    private void processSwitchStm(IElement subElement) {
        SwitchStm switchStm = (SwitchStm) subElement;
        List caseBodies = switchStm.getCaseBodies();
        for (Object object : caseBodies) {
            Block block = (Block) object;
            processBlock(block);
        }
    }

    private void processReturn(IElement element) {
        Return rStm = (Return) element;

        List subElements = rStm.getSubElements();
        processSubElements(element, subElements);
    }

    private void processTryStm(IElement element) {
        TryStm tryStm = (TryStm) element;
        Block tryBody = tryStm.getTryBody();
        processBlock(tryBody);

        int catchCount = tryStm.getCatchCount();
        for (int i = 0; i < catchCount; i++) {
            Block catchBody = tryStm.getCatchBody(i);
            processBlock(catchBody);
        }
    }

    private void processWhileStm(IElement element) {
        WhileStm whileStm = (WhileStm) element;
        Block body = whileStm.getBody();
        processBlock(body);
    }

    private void processIfStm(IElement element) {
        IfStm ifStm = (IfStm) element;

        int size = ifStm.size();
        int elseFlag = 0;
        Block elseBlock = ifStm.getDefaultBlock();
        if (elseBlock != null) {
            processBlock(elseBlock);
            elseFlag = 1;
        }

        for (int i = 0; i < size - elseFlag; i++) {
            // 处理判断语句
            Predicate branchPredicate = ifStm.getBranchPredicate(i);
            List subElements = branchPredicate.getSubElements();
            processSubElements(branchPredicate, subElements);

            // 处理if语句块
            Block branchBody = ifStm.getBranchBody(i);
            processBlock(branchBody);
        }
    }

    private void processAssignment(IElement subElement) {
        Assignment assignment = (Assignment) subElement;

        ILeftExpression left = assignment.getLeft();
        IExpression right = assignment.getRight();

        if (left instanceof Definition) {
            Definition definition = (Definition) left;
            String type = definition.getType();
            if (supportTypes.contains(type)) {
                localVariableMap.put(definition.getIdentifier().getName(), right);
            }
        }


        if (right != null) {
            processIElement(subElement, right);

            List subElements = right.getSubElements();
            processSubElements(right, subElements);
        }


    }


    private void processNewArray(IElement iElement) {
        NewArray newArray = (NewArray) iElement;
        List subElements = newArray.getSubElements();
        processSubElements(newArray, subElements);
    }

    private void processMethod(IElement iElement) {
        jeb.api.ast.Method method = (jeb.api.ast.Method) iElement;

        List parameters = method.getParameters();
        for (Object obj : parameters) {
            processDefinition(obj);

//            for (Object o : elements) {
//                IElement element = (IElement) o;
//                if (element instanceof Identifier) {
//                    processIdentifier(element);
//                } else if (element instanceof Expression) {
//                    Expression ex = (Expression) element;
//                    processExpression(ex);
//                } else {
//                    log2cmd("In processMethod : " + element.toString());
//                }
//            }
        }
    }

    /**
     * 处理变量-标识符
     *
     * @param obj
     */
    private void processDefinition(Object obj) {
        Definition definition = (Definition) obj;
        processSubElements(definition, definition.getSubElements());
    }

//    private void processDefinition(Definition definition, IElement element) {
//        log2cmd(definition.getType());
//        log2cmd(definition.getType());
//    }

    /**
     * 判断逻辑语句
     *
     * @param predicate
     */
    private void processPredicate(Predicate predicate) {
        processSubElements(predicate, predicate.getSubElements());
    }

    private void processExpression(Expression expression) {
        List subElements = expression.getSubElements();
        processSubElements(expression, subElements);
    }

    private void processStaticField(IElement parent, IElement iElement) {
        StaticField staticField = (StaticField) iElement;
        jeb.api.ast.Field field = staticField.getField();

        String signature;
        try {
            signature = field.getSignature();

        } catch (NullPointerException e) {
            return;
        }

        if (signature == null) {
            return;
        }

        // 如果内容是恒变量，则替换掉。
        if (signature.equals(currentStaticFieldSig)) {
            parent.replaceSubElement(staticField, staticFieldMap.get(currentStaticFieldSig));
        } else {
            processSubElements(iElement, staticField.getSubElements());
        }
    }

    private void processArgs(IElement parent, IElement iElement) {
        Call call = (Call) iElement;
        List arguments = call.getArguments();

        if (arguments.size() == 1 && !argsName.startsWith("[")) {
            ArgumentType argumentType = null;
            if (argsName.equals("B")) {
                argumentType = ArgumentType.BYTE;
            } else if (argsName.equals("I")) {
                argumentType = ArgumentType.INT;
            } else if (argsName.equals("C")) {
                argumentType = ArgumentType.CHAR;
            } else if (argsName.equals("J")) {
                argumentType = ArgumentType.LONG;
            } else if (argsName.equals("F")) {
                argumentType = ArgumentType.FLOAT;
            } else if (argsName.equals("D")) {
                argumentType = ArgumentType.DOUBLE;
            } else if (argsName.equals("Ljava/lang/String;")) {
                argumentType = ArgumentType.STRING;
            }

            if (argumentType == null) {
                return;
            }

            Object result = "";
            IExpression expression;
            switch (argumentType) {
                case BYTE:
                    ArrayList<Byte> bytes = new ArrayList<Byte>();
                    expression = (IExpression) arguments.get(0);
                    if (expression instanceof Constant) {
                        bytes.add(((Constant) expression).getByte());

                        if (isManual) {
                            result = myDecode(bytes.get(0));
                        } else {
                            result = reflectInvoke.invokeStatic(aClass, bytes.get(0));
                        }

                        if (result != null) {
                            if (currentMethodSig.endsWith(")[B")) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(new String((byte[]) result)));
                            } else {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(result.toString()));
                            }
                        }
                    }
                    break;
                case SHORT:
                    ArrayList<Short> shorts = new ArrayList<Short>();
                    expression = (IExpression) arguments.get(0);
                    if (expression instanceof Constant) {
                        shorts.add(((Constant) expression).getShort());
                        if (isManual) {
                            result = myDecode(shorts.get(0));
                        } else {
                            result = reflectInvoke.invokeStatic(aClass, shorts.get(0));
                        }

                        if (result != null) {
                            if (currentMethodSig.endsWith(")[B")) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(new String((byte[]) result)));
                            } else {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(result.toString()));
                            }
                        }
                    }
                    break;
                case INT:
                    ArrayList<Integer> integers = new ArrayList<Integer>();
                    expression = (IExpression) arguments.get(0);
                    if (expression instanceof Constant) {
                        integers.add(((Constant) expression).getInt());
                        if (isManual) {
                            result = myDecode(integers.get(0));
                        } else {
                            result = reflectInvoke.invokeStatic(aClass, integers.get(0));
                        }

                        if (result != null) {
                            if (currentMethodSig.endsWith(")[B")) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(new String((byte[]) result)));
                            } else {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(result.toString()));
                            }
                        }
                    }
                    break;
                case LONG:
                    ArrayList<Long> longs = new ArrayList<Long>();
                    expression = (IExpression) arguments.get(0);
                    if (expression instanceof Constant) {
                        longs.add(((Constant) expression).getLong());
                        if (isManual) {
                            result = myDecode(longs.get(0));
                        } else {
                            result = reflectInvoke.invokeStatic(aClass, longs.get(0));
                        }

                        if (result != null) {
                            if (currentMethodSig.endsWith(")[B")) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(new String((byte[]) result)));
                            } else {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(result.toString()));
                            }
                        }
                    }
                    break;
                case FLOAT:
                    ArrayList<Float> floats = new ArrayList<Float>();
                    expression = (IExpression) arguments.get(0);
                    if (expression instanceof Constant) {
                        floats.add(((Constant) expression).getFloat());

                        if (isManual) {
                            result = myDecode(floats.get(0));
                        } else {
                            result = reflectInvoke.invokeStatic(aClass, floats.get(0));
                        }

                        if (result != null) {
                            if (currentMethodSig.endsWith(")[B")) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(new String((byte[]) result)));
                            } else {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(result.toString()));
                            }
                        }
                    }
                    break;
                case DOUBLE:
                    ArrayList<Double> doubles = new ArrayList<Double>();
                    expression = (IExpression) arguments.get(0);
                    if (expression instanceof Constant) {
                        doubles.add(((Constant) expression).getDouble());

                        if (isManual) {
                            result = myDecode(doubles.get(0));
                        } else {
                            result = reflectInvoke.invokeStatic(aClass, doubles.get(0));
                        }

                        if (result != null) {
                            if (currentMethodSig.endsWith(")[B")) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(new String((byte[]) result)));
                            } else {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(result.toString()));
                            }
                        }
                    }
                    break;
                case CHAR:
                    ArrayList<Character> characters = new ArrayList<Character>();
                    expression = (IExpression) arguments.get(0);
                    if (expression instanceof Constant) {
                        characters.add(((Constant) expression).getChar());

                        if (isManual) {
                            result = myDecode(characters.get(0));
                        } else {
                            result = reflectInvoke.invokeStatic(aClass, characters.get(0));
                        }

                        if (result != null) {
                            if (currentMethodSig.endsWith(")[B")) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(new String((byte[]) result)));
                            } else {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(result.toString()));
                            }
                        }
                    }
                    break;
                case STRING:
                    Object o = arguments.get(0);

                    String argStr = null;
                    if (o instanceof StaticField) {
                        StaticField staticField = (StaticField) o;
                        Constant constant = staticFieldMap.get(staticField.getField().getSignature());
                        if (constant != null) {
                            argStr = constant.getString();
                        }
                    } else if (o instanceof Constant) {
                        Constant constant = (Constant) o;
                        argStr = constant.getString();
                    }

                    if (argStr == null) {
                        return;
                    }

                    if (isManual) {
                        result = myDecode(argStr);
                    } else {
                        result = reflectInvoke.invokeStatic(aClass, argStr);
                    }

                    if (result != null) {
                        if (currentMethodSig.endsWith(")[B")) {
                            parent.replaceSubElement(iElement, cstBuilder.buildString(new String((byte[]) result)));
                        } else {
                            parent.replaceSubElement(iElement, cstBuilder.buildString(result.toString()));
                        }
                    }
                    break;
            }
        } else if (argsName.equals("II")) {
            ArrayList<Integer> arrayList = new ArrayList<Integer>();
            for (Object obj : arguments) {
                IExpression expression = (IExpression) obj;
                if (expression instanceof Constant) {
                    arrayList.add(((Constant) expression).getInt());
                }
            }

            Object o;

            if (arrayList.size() != 2) {
                return;
            }


            if (isManual) {
                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                if (decodeMethodName.equals("myDecode")) {
                    String s = myDecode(arrayList.get(0), arrayList.get(1));
                    parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                }

                return;
            }

            o = reflectInvoke.invokeStatic(aClass, arrayList.get(0), arrayList.get(1));
            if (o != null)
                parent.replaceSubElement(iElement, cstBuilder.buildString(o.toString()));
        } else if (argsName.equals("III")) {
            ArrayList<Integer> arrayList = new ArrayList<Integer>();
            for (Object obj : arguments) {
                IExpression expression = (IExpression) obj;
                if (expression instanceof Constant) {
                    arrayList.add(((Constant) expression).getInt());
                }
            }

            Object o;

            if (arrayList.size() != 3) {
                return;
            }

            if (isManual) {
                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                if (decodeMethodName.equals("myDecode")) {
                    String s = myDecode(arrayList.get(0), arrayList.get(1), arrayList.get(2));
                    parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                }

                return;
            }

            o = reflectInvoke.invokeStatic(aClass, arrayList.get(0), arrayList.get(1), arrayList.get(2));
            if (o != null)
                parent.replaceSubElement(iElement, cstBuilder.buildString(o.toString()));
        } else if (argsName.equals("Ljava/lang/String;Ljava/lang/String;")) {
            Object o1 = arguments.get(0);
            Object o2 = arguments.get(1);

            String arg1 = null;
            String arg2 = null;
            if (o1 instanceof StaticField) {
                StaticField staticField = (StaticField) o1;
                Constant constant = staticFieldMap.get(staticField.getField().getSignature());
                if (constant != null) {
                    arg1 = constant.getString();
                }
            } else if (o1 instanceof Constant) {
                Constant constant = (Constant) o1;
                arg1 = constant.getString();
            }


            if (o2 instanceof StaticField) {
                StaticField staticField = (StaticField) o2;
                Constant constant = staticFieldMap.get(staticField.getField().getSignature());
                if (constant != null) {
                    arg2 = constant.getString();
                }
            } else if (o2 instanceof Constant) {
                Constant constant = (Constant) o2;
                arg2 = constant.getString();
            }

            if (arg1 == null || arg2 == null) {
                return;
            }

            if (isManual) {
                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                if (decodeMethodName.equals("myDecode")) {
                    String s = myDecode(arg1, arg2);
                    parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                }

                return;
            }

            o1 = reflectInvoke.invokeStatic(aClass, arg1, arg2);
            if (o1 == null) {
                return;
            }

            if (currentMethodSig.endsWith(")[B")) {
                byte[] bytes = (byte[]) o1;
                parent.replaceSubElement(iElement, cstBuilder.buildString(new String(bytes)));
            } else {
                parent.replaceSubElement(iElement, cstBuilder.buildString(o1.toString()));
            }

        } else if (argsName.startsWith("[")) {

            ArgumentType argumentType = ArgumentType.BYTE;
            if (argsName.equals("[B")) {
                argumentType = ArgumentType.BYTE;
            } else if (argsName.equals("[I")) {
                argumentType = ArgumentType.INT;
            } else if (argsName.equals("[C")) {
                argumentType = ArgumentType.CHAR;
            } else if (argsName.equals("[J")) {
                argumentType = ArgumentType.LONG;
            } else if (argsName.equals("[F")) {
                argumentType = ArgumentType.FLOAT;
            } else if (argsName.equals("[D")) {
                argumentType = ArgumentType.DOUBLE;
            } else if (argsName.equals("[Ljava/lang/String;")) {
                argumentType = ArgumentType.STRING;
            }

            Object o = arguments.get(0);
            if (o instanceof Identifier) {
                Identifier identifier = (Identifier) o;
                String name = identifier.getName();
                Object obj = localVariableMap.get(name);
                if (obj != null && obj instanceof NewArray) {
                    NewArray newArray = (NewArray) obj;
                    List initialValues = newArray.getInitialValues();
                    if (initialValues == null) {
                        return;
                    }

                    int size = initialValues.size();

                    Object resultObj = null;
                    switch (argumentType) {
                        case BYTE:
                            byte[] bytes = new byte[size];

                            for (int i = 0; i < size; i++) {
                                Constant constant = (Constant) initialValues.get(i);
                                bytes[i] = constant.getByte();
                            }

                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    resultObj = myDecode(bytes);
                                }
                            } else {
                                resultObj = reflectInvoke.invokeStatic(aClass, bytes);
                            }

                            if (resultObj != null) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                            }
                            break;
                        case INT:
                            int[] intArr = new int[size];
                            for (int i = 0; i < size; i++) {
                                Constant constant = (Constant) initialValues.get(i);
                                intArr[i] = constant.getInt();
                            }

                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    resultObj = myDecode(intArr);
                                }
                            } else {
                                resultObj = reflectInvoke.invokeStatic(aClass, intArr);
                            }

                            if (resultObj != null) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                            }
                            break;
                        case LONG:
                            long[] longs = new long[size];
                            for (int i = 0; i < size; i++) {
                                Constant constant = (Constant) initialValues.get(i);
                                longs[i] = constant.getLong();
                            }
                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    resultObj = myDecode(longs);
                                }
                            } else {
                                resultObj = reflectInvoke.invokeStatic(aClass, longs);
                            }

                            if (resultObj != null) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                            }
                            break;
                        case STRING:
                            String[] strs = new String[size];
                            for (int i = 0; i < size; i++) {
                                Constant constant = (Constant) initialValues.get(i);
                                strs[i] = constant.getString();
                            }
                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    resultObj = myDecode(strs);
                                }
                            } else {
                                resultObj = reflectInvoke.invokeStatic(aClass, strs);
                            }

                            if (resultObj != null) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                            }
                            break;
                        case CHAR:
                            char[] chars = new char[size];
                            for (int i = 0; i < size; i++) {
                                Constant constant = (Constant) initialValues.get(i);
                                chars[i] = constant.getChar();
                            }
                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    resultObj = myDecode(chars);
                                }
                            } else {
                                resultObj = reflectInvoke.invokeStatic(aClass, chars);
                            }

                            if (resultObj != null) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                            }
                            break;
                        case DOUBLE:
                            double[] doubles = new double[size];
                            for (int i = 0; i < size; i++) {
                                Constant constant = (Constant) initialValues.get(i);
                                doubles[i] = constant.getDouble();
                            }
                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    resultObj = myDecode(doubles);
                                }
                            } else {
                                resultObj = reflectInvoke.invokeStatic(aClass, doubles);
                            }

                            if (resultObj != null) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                            }
                            break;
                        case FLOAT:
                            float[] floats = new float[size];
                            for (int i = 0; i < size; i++) {
                                Constant constant = (Constant) initialValues.get(i);
                                floats[i] = constant.getFloat();
                            }
                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    resultObj = myDecode(floats);
                                }
                            } else {
                                resultObj = reflectInvoke.invokeStatic(aClass, floats);
                            }

                            if (resultObj != null) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                            }
                            break;
                        case SHORT:
                            short[] shorts = new short[size];
                            for (int i = 0; i < size; i++) {
                                Constant constant = (Constant) initialValues.get(i);
                                shorts[i] = constant.getShort();
                            }
                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    resultObj = myDecode(shorts);
                                }
                            } else {
                                resultObj = reflectInvoke.invokeStatic(aClass, shorts);
                            }

                            if (resultObj != null) {
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                            }
                            break;
                    }
                }
            } else if (o instanceof StaticField) {
                StaticField staticField = (StaticField) o;
                jeb.api.ast.Field field = staticField.getField();

                IExpression initialValue = field.getInitialValue();
                if (initialValue == null) {
                    String classSig = getClassSig(field.getSignature());

                    Class clz = findClass(classSig);
                    if (clz != null) {
                        ReflectAccess reflectAccess = new ReflectAccess(field.getName());
                        Object result = reflectAccess.getStaticField(clz, field.getName());

                        if (result != null) {
                            if (isManual) {
                                String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                                if (decodeMethodName.equals("myDecode")) {
                                    String s = myDecode((byte[]) result);
                                    parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                                }

                                return;
                            }

                            byte[] bytes = (byte[]) result;
                            String byteStr = "";
                            int sum = 0;
                            for (byte b : bytes) {
                                sum += b;
                                byteStr = byteStr + " " + b;
                            }

                            if (sum == 0) {
                                System.out.println("Could not get field : " + field.getSignature());
                                return;
                            }

                            System.out.println(sum + " : " + byteStr);

                            Object resultObj = reflectInvoke.invokeStatic(aClass, (byte[]) result);
                            System.out.println("Result : " + resultObj.toString());
                            if (resultObj != null)
                                parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                        } else {
                            System.out.println("Could not reflect acess the field");
                        }
                    } else {
                        Assignment assignment = (Assignment) staticAssignmentMap.get(field.getSignature());
                        IExpression right = assignment.getRight();
                        processNewArrayArgs(parent, iElement, right);
                    }
                }
            } else if (o instanceof NewArray) {
                NewArray newArray = (NewArray) o;
                List initialValues = newArray.getInitialValues();
                if (initialValues == null) {
                    return;
                }

                int size = initialValues.size();
                Object resultObj = null;

                switch (argumentType) {
                    case BYTE:
                        byte[] bytes = new byte[size];

                        for (int i = 0; i < size; i++) {
                            Constant constant = (Constant) initialValues.get(i);
                            bytes[i] = constant.getByte();
                        }

                        if (isManual) {
                            String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                            if (decodeMethodName.equals("myDecode")) {
                                String s = myDecode(bytes);
                                parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                            }

                            return;
                        }

                        resultObj = reflectInvoke.invokeStatic(aClass, bytes);
                        System.out.print("String : " + resultObj);
                        if (resultObj != null)
                            parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                        break;
                    case SHORT:
                        short[] shorts = new short[size];

                        for (int i = 0; i < size; i++) {
                            Constant constant = (Constant) initialValues.get(i);
                            shorts[i] = constant.getShort();
                        }

                        if (isManual) {
                            String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                            if (decodeMethodName.equals("myDecode")) {
                                String s = myDecode(shorts);
                                parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                            }

                            return;
                        }

                        resultObj = reflectInvoke.invokeStatic(aClass, shorts);
                        System.out.print("String : " + resultObj);
                        if (resultObj != null)
                            parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                        break;
                    case INT:
                        int[] ints = new int[size];

                        for (int i = 0; i < size; i++) {
                            Constant constant = (Constant) initialValues.get(i);
                            ints[i] = constant.getInt();
                        }

                        if (isManual) {
                            String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                            if (decodeMethodName.equals("myDecode")) {
                                String s = myDecode(ints);
                                parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                            }

                            return;
                        }

                        resultObj = reflectInvoke.invokeStatic(aClass, ints);
                        if (resultObj != null)
                            parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                        break;
                    case FLOAT:
                        float[] floats = new float[size];

                        for (int i = 0; i < size; i++) {
                            Constant constant = (Constant) initialValues.get(i);
                            floats[i] = constant.getFloat();
                        }

                        if (isManual) {
                            String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                            if (decodeMethodName.equals("myDecode")) {
                                String s = myDecode(floats);
                                parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                            }

                            return;
                        }

                        resultObj = reflectInvoke.invokeStatic(aClass, floats);
                        System.out.print("String : " + resultObj);
                        if (resultObj != null)
                            parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                        break;
                    case DOUBLE:
                        double[] doubles = new double[size];

                        for (int i = 0; i < size; i++) {
                            Constant constant = (Constant) initialValues.get(i);
                            doubles[i] = constant.getDouble();
                        }

                        if (isManual) {
                            String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                            if (decodeMethodName.equals("myDecode")) {
                                String s = myDecode(doubles);
                                parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                            }

                            return;
                        }

                        resultObj = reflectInvoke.invokeStatic(aClass, doubles);
                        if (resultObj != null)
                            parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
                        break;
                    case CHAR:
                        char[] chars = new char[size];

                        for (int i = 0; i < size; i++) {
                            Constant constant = (Constant) initialValues.get(i);
                            chars[i] = constant.getChar();
                        }

                        if (isManual) {
                            String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                            if (decodeMethodName.equals("myDecode")) {
                                String s = myDecode(chars);
                                parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                            }

                            return;
                        }

                        resultObj = reflectInvoke.invokeStatic(aClass, chars);
                        break;
                    case STRING:
                        String[] strings = new String[size];

                        for (int i = 0; i < size; i++) {
                            Constant constant = (Constant) initialValues.get(i);
                            strings[i] = constant.getString();
                        }

                        if (isManual) {
                            String decodeMethodName = decryptMethodMap.get(currentMethodSig);
                            if (decodeMethodName.equals("myDecode")) {
                                String s = myDecode(strings);
                                parent.replaceSubElement(iElement, cstBuilder.buildString(s));
                            }

                            return;
                        }

                        resultObj = reflectInvoke.invokeStatic(aClass, strings);
                        break;
                }

                if (resultObj != null)
                    parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
            }
        }
    }

    private String myDecode(Double aDouble) {
        // TODO Please don't rename the function name, Just add your decoding code here.
        return null;
    }

    private String myDecode(Long aLong) {
        // TODO Please don't rename the function name, Just add your decoding code here.
        return null;
    }

    private String myDecode(Float aFloat) {
        // TODO Please don't rename the function name, Just add your decoding code here.
        return null;
    }

    private void processNewArrayArgs(IElement parent, IElement iElement, Object o) {
        NewArray newArray = (NewArray) o;
        List initialValues = newArray.getInitialValues();
        if (initialValues == null) {
            return;
        }

        int size = initialValues.size();
        byte[] bytes = new byte[size];

        for (int i = 0; i < size; i++) {
            Constant constant = (Constant) initialValues.get(i);
            bytes[i] = constant.getByte();
        }

        if (isManual) {
            String decodeMethodName = decryptMethodMap.get(currentMethodSig);
            if (decodeMethodName.equals("myDecode")) {
                String s = myDecode(bytes);
                parent.replaceSubElement(iElement, cstBuilder.buildString(s));
            }

            return;
        }

        Object resultObj = reflectInvoke.invokeStatic(aClass, bytes);
        if (resultObj != null)
            parent.replaceSubElement(iElement, cstBuilder.buildString(resultObj.toString()));
    }

    private void processCall(IElement parent, IElement subElement) {
        Call call = (Call) subElement;

        jeb.api.ast.Method method = call.getMethod();
        String sig = method.getSignature();

        // 如果这个刚刚好是解密的方法，那么直接获取参数进行解密。
        if (sig.equals(currentMethodSig)) {
            processArgs(parent, subElement);
            return;
        }

        List subElements = call.getSubElements();
        processSubElements(subElement, subElements);
    }

    private void processNew(IElement parent, IElement element) {
        New aNew = (New) element;

        // "Ljava/lang/String;-><init>([B)V"
        if (aNew.getMethod().getSignature().equals(currentMethodSig)) {
//            jeb.print(currentMethodSig);
            List arguments = aNew.getArguments();
            if (arguments.size() == 1) {
                Object o = arguments.get(0);

                if (o instanceof NewArray) {
                    NewArray newArray = (NewArray) o;
                    String type = newArray.getType();
                    if (type.equals("[B")) {
                        List initialValues = newArray.getInitialValues();
                        if (initialValues == null) {
                            return;
                        }

                        int size = initialValues.size();
                        byte[] bytes = new byte[size];

                        for (int i = 0; i < size; i++) {
                            Object obj = initialValues.get(i);

                            if (obj instanceof Constant) {
                                Constant constant = (Constant) initialValues.get(i);
                                bytes[i] = constant.getByte();
                            } else if (obj instanceof Identifier) {
                                return;
                            }
                        }

                        parent.replaceSubElement(element, cstBuilder.buildString(new String(bytes)));
                        return;
                    }
                }
            }
        }

        List subElements = aNew.getSubElements();
        processSubElements(aNew, subElements);
    }

    private String getArgsName(String methodSig) {
        int startIndex = methodSig.indexOf("(") + 1;
        int endIndex = methodSig.lastIndexOf(")");
        return methodSig.substring(startIndex, endIndex);
    }

    /**
     * TODO 参数仍然需要适配
     * @param methodSig
     * @return
     */
    private Class<?>[] getArgs(String methodSig) {
        int startIndex = methodSig.indexOf("(") + 1;
        int endIndex = methodSig.lastIndexOf(")");
        String argsName = methodSig.substring(startIndex, endIndex);
        Decode.argsName = argsName;

        if (argsName.equals("")) {
            return new Class<?>[0];
        }

        if (argsName.equals("I")) {
            return new Class[]{Integer.TYPE};
        }

        if (argsName.equals("II")) {
            return new Class[]{Integer.TYPE, Integer.TYPE};
        }

        if (argsName.equals("III")) {
            return new Class[]{Integer.TYPE, Integer.TYPE, Integer.TYPE};
        }
        if (argsName.equals("[B")) {
            return new Class[]{byte[].class};
        }

        if (argsName.equals("[I")) {
            return new Class[]{int[].class};
        }

        if (argsName.equals("[C")) {
            return new Class[]{char[].class};
        }

        if (argsName.equals("[Ljava/lang/String;")) {
            return new Class[]{String[].class};
        }

        if (argsName.equals("Ljava/lang/String;")) {
            return new Class[]{String.class};
        }

        if (argsName.equals("Ljava/lang/String;Ljava/lang/String;")) {
            return new Class[]{String.class, String.class};
        }

        return null;
    }

    private String getMethodName(String methodSig) {
        int startIndex = methodSig.indexOf(">") + 1;
        int endIndex = methodSig.lastIndexOf("(");
        return methodSig.substring(startIndex, endIndex);
    }

    /**
     * 通过反射获得该类
     *
     * @param className like java.lang.Thread
     * @return class 返回反射的类实例，若为null，则反射失败。
     */
    private Class findClass(String className) {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {

        } catch (NoClassDefFoundError e) {

        } catch (ExceptionInInitializerError e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Error e) {
            e.printStackTrace();
        }

        return null;
    }

    private String getClassSig(String mtd) {
        String pkg = mtd.split(";->")[0];
        return pkg.replace('/', '.').substring(1, pkg.length());
    }

    /**
     * 参数类型
     */
    enum ArgumentType {
        INT, LONG, STRING, BYTE, CHAR, DOUBLE, FLOAT, SHORT
    }
}

class ReflectAccess {

    private String fieldName;

    ReflectAccess(String fieldName) {
        this.fieldName = fieldName;
    }

    public static ReflectAccess field(String name) {
        return new ReflectAccess(name);
    }

    public void set(Object obj, Object value) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field field = clazz.getDeclaredField(this.fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    /**
     * 通过反射获取该类的成员变量值
     *
     * @param clazz
     * @param fieldName
     * @return
     */
    public Object getStaticField(Class clazz, String fieldName) {
        Field field;
        try {
            field = clazz.getDeclaredField(fieldName);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
            return null;
        }

        field.setAccessible(true);

        Object o = null;
        try {
            o = field.get(clazz);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

        return o;
    }

    /**
     * 通过反射获取该类的成员变量值
     *
     * @param clazz
     * @param fieldName
     * @return
     */
    public Object getField(Class clazz, String fieldName) {
        Field field;
        try {
            field = clazz.getDeclaredField(fieldName);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
            return null;
        }

        field.setAccessible(true);

        Object o = null;
        try {
            o = field.get(clazz.newInstance());
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        }

        return o;
    }

    public Object get(Class clazz) {
        Field field;
        try {
            field = clazz.getDeclaredField(this.fieldName);
        } catch (NoSuchFieldException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            return null;
        }

        field.setAccessible(true);

        Object o = null;
        try {
            o = field.get(clazz);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
        }

        return o;
    }

    public Object get(Object obj) throws NoSuchFieldException, IllegalAccessException {
        Class clazz = obj.getClass();
        Field field = clazz.getDeclaredField(this.fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }
}

class ReflectInvoke {

    private Class<?>[] argClasses;
    private String methodName;


    ReflectInvoke(String methodName, Class<?>[] argClasses) {
        this.methodName = methodName;
        this.argClasses = argClasses;
    }

    public static ReflectInvoke method(String methodName, Class<?>... argClasses) {
        return new ReflectInvoke(methodName, argClasses);
    }

    public Class<?>[] getArgClasses() {
        return argClasses;
    }

    public String getMethodName() {
        return methodName;
    }

    public Object invoke(Object obj, Object... args)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class[] argClazz = new Class[args.length];
        for (int i = 0; i < argClazz.length; i++) {
            argClazz[i] = args[i].getClass();
        }

        Method method = obj.getClass().getDeclaredMethod(methodName, argClasses);
        method.setAccessible(true);
        return method.invoke(obj, args);
    }

    public Object invokeStatic(Class clazz, Object... args) {

        Class[] argClazz = new Class[args.length];
        for (int i = 0; i < argClazz.length; i++) {
            argClazz[i] = args[i].getClass();
        }

        Method method;
        try {
            method = clazz.getDeclaredMethod(methodName, argClasses);
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
            return null;
        }

        if (!method.isAccessible()) {
            method.setAccessible(true);
        }

        Object obj = null;
        try {
            obj = method.invoke(clazz, args);
        } catch (Exception e) {
            System.out.print(".");
        } catch (Error e) {
            System.out.print(".");
        }

        return obj;
    }
}
