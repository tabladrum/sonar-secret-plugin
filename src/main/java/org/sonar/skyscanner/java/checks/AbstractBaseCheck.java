package org.sonar.skyscanner.java.checks;

import com.google.common.collect.ImmutableList;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.AssignmentExpressionTree;
import org.sonar.plugins.java.api.tree.BinaryExpressionTree;
import org.sonar.plugins.java.api.tree.LiteralTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.VariableTree;

import java.util.List;
import java.util.Objects;

abstract class AbstractBaseCheck extends IssuableSubscriptionVisitor {
    @Override
    public List<Tree.Kind> nodesToVisit() {
        return ImmutableList.of(
                Tree.Kind.ASSIGNMENT,
                Tree.Kind.EQUAL_TO,
                Tree.Kind.VARIABLE
        );
    }

    @Override
    public void visitNode(Tree tree) {
        String variable = "";
        String value = "";

        if (tree.is(Tree.Kind.VARIABLE)) {
            VariableTree obj = (VariableTree)tree;

            if (obj.initializer() != null && Objects.requireNonNull(obj.initializer()).is(Tree.Kind.STRING_LITERAL)) {
                variable = obj.simpleName().toString();
                value = ((LiteralTree) Objects.requireNonNull(obj.initializer())).value();
            }

        } else if (tree.is(Tree.Kind.ASSIGNMENT)) {
            AssignmentExpressionTree obj = (AssignmentExpressionTree)tree;

            if (obj.expression().is(Tree.Kind.STRING_LITERAL)) {
                variable = obj.variable().toString();
                value = ((LiteralTree)obj.expression()).value();
            }

        } else if (tree.is(Tree.Kind.EQUAL_TO)) {
            BinaryExpressionTree obj = (BinaryExpressionTree)tree;

            if (obj.leftOperand().is(Tree.Kind.IDENTIFIER) && obj.rightOperand().is(Tree.Kind.STRING_LITERAL)) {
                variable = obj.leftOperand().toString();
                value = ((LiteralTree)obj.rightOperand()).value();
            } else if (obj.rightOperand().is(Tree.Kind.IDENTIFIER) && obj.leftOperand().is(Tree.Kind.STRING_LITERAL)) {
                variable = obj.rightOperand().toString();
                value = ((LiteralTree)obj.leftOperand()).value();
            }

        }

        if (!value.isEmpty()) {
            validate(tree, variable, value);
        }
    }

    protected abstract void validate(Tree tree, String variable, String value);
}
