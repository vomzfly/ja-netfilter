package com.janetfilter.plugins.dns;

import com.janetfilter.core.models.FilterRule;
import com.janetfilter.core.plugin.MyTransformer;
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.tree.*;

import java.util.List;

import static jdk.internal.org.objectweb.asm.Opcodes.*;

public class InetAddressTransformer implements MyTransformer {
    private final List<FilterRule> rules;

    public InetAddressTransformer(List<FilterRule> rules) {
        this.rules = rules;
    }

    @Override
    public String getHookClassName() {
        return "java/net/InetAddress";
    }

    @Override
    public byte[] transform(String className, byte[] classBytes, int order) throws Exception {
        DNSFilter.setRules(rules);

        ClassReader reader = new ClassReader(classBytes);
        ClassNode node = new ClassNode(ASM5);
        reader.accept(node, 0);

        for (MethodNode m : node.methods) {
            if ("getAllByName".equals(m.name) && "(Ljava/lang/String;Ljava/net/InetAddress;)[Ljava/net/InetAddress;".equals(m.desc)) {
                InsnList list = new InsnList();
                list.add(new VarInsnNode(ALOAD, 0));
                list.add(new MethodInsnNode(INVOKESTATIC, "com/janetfilter/plugins/dns/DNSFilter", "testQuery", "(Ljava/lang/String;)Ljava/lang/String;", false));
                list.add(new InsnNode(POP));

                m.instructions.insert(list);
                continue;
            }

            if ("isReachable".equals(m.name) && "(Ljava/net/NetworkInterface;II)Z".equals(m.desc)) {
                InsnList list = new InsnList();
                list.add(new VarInsnNode(ALOAD, 0));
                list.add(new MethodInsnNode(INVOKESTATIC, "com/janetfilter/plugins/dns/DNSFilter", "testReachable", "(Ljava/net/InetAddress;)Ljava/lang/Object;", false));
                list.add(new VarInsnNode(ASTORE, 4));
                list.add(new InsnNode(ACONST_NULL));
                list.add(new VarInsnNode(ALOAD, 4));

                LabelNode label1 = new LabelNode();
                list.add(new JumpInsnNode(IF_ACMPEQ, label1));
                list.add(new InsnNode(ICONST_0));
                list.add(new InsnNode(IRETURN));
                list.add(label1);

                m.instructions.insert(list);
            }
        }

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        node.accept(writer);

        return writer.toByteArray();
    }
}
