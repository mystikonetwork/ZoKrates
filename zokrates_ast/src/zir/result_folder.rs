// Generic walk through ZIR. Not mutating in place

use crate::common::expressions::{BinaryOrExpression, IdentifierOrExpression, UnaryOrExpression};
use crate::common::ResultFold;
use crate::common::WithSpan;
use crate::zir::types::UBitwidth;
use crate::zir::*;
use zokrates_field::Field;

impl<'ast, T: Field, F: ResultFolder<'ast, T>> ResultFold<F, F::Error>
    for FieldElementExpression<'ast, T>
{
    fn fold(self, f: &mut F) -> Result<Self, F::Error> {
        f.fold_field_expression(self)
    }
}

impl<'ast, T: Field, F: ResultFolder<'ast, T>> ResultFold<F, F::Error>
    for BooleanExpression<'ast, T>
{
    fn fold(self, f: &mut F) -> Result<Self, F::Error> {
        f.fold_boolean_expression(self)
    }
}

impl<'ast, T: Field, F: ResultFolder<'ast, T>> ResultFold<F, F::Error> for UExpression<'ast, T> {
    fn fold(self, f: &mut F) -> Result<Self, F::Error> {
        f.fold_uint_expression(self)
    }
}
pub trait ResultFolder<'ast, T: Field>: Sized {
    type Error;

    fn fold_program(&mut self, p: ZirProgram<'ast, T>) -> Result<ZirProgram<'ast, T>, Self::Error> {
        fold_program(self, p)
    }

    fn fold_function(
        &mut self,
        f: ZirFunction<'ast, T>,
    ) -> Result<ZirFunction<'ast, T>, Self::Error> {
        fold_function(self, f)
    }

    fn fold_parameter(&mut self, p: Parameter<'ast>) -> Result<Parameter<'ast>, Self::Error> {
        Ok(Parameter {
            id: self.fold_variable(p.id)?,
            ..p
        })
    }

    fn fold_name(&mut self, n: Identifier<'ast>) -> Result<Identifier<'ast>, Self::Error> {
        Ok(n)
    }

    fn fold_variable(&mut self, v: Variable<'ast>) -> Result<Variable<'ast>, Self::Error> {
        Ok(Variable {
            id: self.fold_name(v.id)?,
            ..v
        })
    }

    fn fold_assignee(&mut self, a: ZirAssignee<'ast>) -> Result<ZirAssignee<'ast>, Self::Error> {
        self.fold_variable(a)
    }

    fn fold_assembly_constraint(
        &mut self,
        s: AssemblyConstraint<'ast, T>,
    ) -> Result<Vec<ZirAssemblyStatement<'ast, T>>, Self::Error> {
        fold_assembly_constraint(self, s)
    }

    fn fold_assembly_assignment(
        &mut self,
        s: AssemblyAssignment<'ast, T>,
    ) -> Result<Vec<ZirAssemblyStatement<'ast, T>>, Self::Error> {
        fold_assembly_assignment(self, s)
    }

    fn fold_assembly_statement(
        &mut self,
        s: ZirAssemblyStatement<'ast, T>,
    ) -> Result<Vec<ZirAssemblyStatement<'ast, T>>, Self::Error> {
        fold_assembly_statement(self, s)
    }

    fn fold_assembly_statement_cases(
        &mut self,
        s: ZirAssemblyStatement<'ast, T>,
    ) -> Result<Vec<ZirAssemblyStatement<'ast, T>>, Self::Error> {
        fold_assembly_statement_cases(self, s)
    }

    fn fold_statement(
        &mut self,
        s: ZirStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_statement(self, s)
    }

    fn fold_statement_cases(
        &mut self,
        s: ZirStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_statement_cases(self, s)
    }

    fn fold_definition_statement(
        &mut self,
        s: DefinitionStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_definition_statement(self, s)
    }

    fn fold_multiple_definition_statement(
        &mut self,
        s: MultipleDefinitionStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_multiple_definition_statement(self, s)
    }

    fn fold_return_statement(
        &mut self,
        s: ReturnStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_return_statement(self, s)
    }

    fn fold_log_statement(
        &mut self,
        s: LogStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_log_statement(self, s)
    }

    fn fold_assembly_block(
        &mut self,
        s: AssemblyBlockStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_assembly_block(self, s)
    }

    fn fold_assertion_statement(
        &mut self,
        s: AssertionStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_assertion_statement(self, s)
    }

    fn fold_if_else_statement(
        &mut self,
        s: IfElseStatement<'ast, T>,
    ) -> Result<Vec<ZirStatement<'ast, T>>, Self::Error> {
        fold_if_else_statement(self, s)
    }

    fn fold_expression(
        &mut self,
        e: ZirExpression<'ast, T>,
    ) -> Result<ZirExpression<'ast, T>, Self::Error> {
        match e {
            ZirExpression::FieldElement(e) => Ok(self.fold_field_expression(e)?.into()),
            ZirExpression::Boolean(e) => Ok(self.fold_boolean_expression(e)?.into()),
            ZirExpression::Uint(e) => Ok(self.fold_uint_expression(e)?.into()),
        }
    }

    fn fold_expression_list(
        &mut self,
        es: ZirExpressionList<'ast, T>,
    ) -> Result<ZirExpressionList<'ast, T>, Self::Error> {
        match es {
            ZirExpressionList::EmbedCall(embed, generics, arguments) => {
                Ok(ZirExpressionList::EmbedCall(
                    embed,
                    generics,
                    arguments
                        .into_iter()
                        .map(|a| self.fold_expression(a))
                        .collect::<Result<_, _>>()?,
                ))
            }
        }
    }

    fn fold_identifier_expression<
        E: Expr<'ast, T> + Id<'ast, T> + ResultFold<Self, Self::Error>,
    >(
        &mut self,
        ty: &E::Ty,
        id: IdentifierExpression<'ast, E>,
    ) -> Result<IdentifierOrExpression<Identifier<'ast>, E, E::Inner>, Self::Error> {
        fold_identifier_expression(self, ty, id)
    }

    fn fold_conditional_expression<
        E: Expr<'ast, T> + ResultFold<Self, Self::Error> + Conditional<'ast, T>,
    >(
        &mut self,
        ty: &E::Ty,
        e: ConditionalExpression<'ast, T, E>,
    ) -> Result<ConditionalOrExpression<'ast, T, E>, Self::Error> {
        fold_conditional_expression(self, ty, e)
    }

    #[allow(clippy::type_complexity)]
    fn fold_binary_expression<
        L: Expr<'ast, T> + PartialEq + ResultFold<Self, Self::Error>,
        R: Expr<'ast, T> + PartialEq + ResultFold<Self, Self::Error>,
        E: Expr<'ast, T> + PartialEq + ResultFold<Self, Self::Error>,
        Op,
    >(
        &mut self,
        ty: &E::Ty,
        e: BinaryExpression<Op, L, R, E>,
    ) -> Result<BinaryOrExpression<Op, L, R, E, E::Inner>, Self::Error> {
        fold_binary_expression(self, ty, e)
    }

    fn fold_unary_expression<
        In: Expr<'ast, T> + PartialEq + ResultFold<Self, Self::Error>,
        E: Expr<'ast, T> + PartialEq + ResultFold<Self, Self::Error>,
        Op,
    >(
        &mut self,
        ty: &E::Ty,
        e: UnaryExpression<Op, In, E>,
    ) -> Result<UnaryOrExpression<Op, In, E, E::Inner>, Self::Error> {
        fold_unary_expression(self, ty, e)
    }

    fn fold_select_expression<
        E: Clone + Expr<'ast, T> + ResultFold<Self, Self::Error> + Select<'ast, T>,
    >(
        &mut self,
        ty: &E::Ty,
        e: SelectExpression<'ast, T, E>,
    ) -> Result<SelectOrExpression<'ast, T, E>, Self::Error> {
        fold_select_expression(self, ty, e)
    }

    fn fold_field_expression(
        &mut self,
        e: FieldElementExpression<'ast, T>,
    ) -> Result<FieldElementExpression<'ast, T>, Self::Error> {
        fold_field_expression(self, e)
    }

    fn fold_field_expression_cases(
        &mut self,
        e: FieldElementExpression<'ast, T>,
    ) -> Result<FieldElementExpression<'ast, T>, Self::Error> {
        fold_field_expression_cases(self, e)
    }

    fn fold_boolean_expression(
        &mut self,
        e: BooleanExpression<'ast, T>,
    ) -> Result<BooleanExpression<'ast, T>, Self::Error> {
        fold_boolean_expression(self, e)
    }

    fn fold_boolean_expression_cases(
        &mut self,
        e: BooleanExpression<'ast, T>,
    ) -> Result<BooleanExpression<'ast, T>, Self::Error> {
        fold_boolean_expression_cases(self, e)
    }

    fn fold_uint_expression(
        &mut self,
        e: UExpression<'ast, T>,
    ) -> Result<UExpression<'ast, T>, Self::Error> {
        fold_uint_expression(self, e)
    }

    fn fold_uint_expression_inner(
        &mut self,
        bitwidth: UBitwidth,
        e: UExpressionInner<'ast, T>,
    ) -> Result<UExpressionInner<'ast, T>, Self::Error> {
        fold_uint_expression_inner(self, bitwidth, e)
    }

    fn fold_uint_expression_cases(
        &mut self,
        bitwidth: UBitwidth,
        e: UExpressionInner<'ast, T>,
    ) -> Result<UExpressionInner<'ast, T>, Self::Error> {
        fold_uint_expression_cases(self, bitwidth, e)
    }
}

pub fn fold_assembly_assignment<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: AssemblyAssignment<'ast, T>,
) -> Result<Vec<ZirAssemblyStatement<'ast, T>>, F::Error> {
    let assignees = s
        .assignee
        .into_iter()
        .map(|a| f.fold_assignee(a))
        .collect::<Result<_, _>>()?;
    let expression = f.fold_function(s.expression)?;
    Ok(vec![ZirAssemblyStatement::assignment(
        assignees, expression,
    )])
}

pub fn fold_assembly_constraint<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: AssemblyConstraint<'ast, T>,
) -> Result<Vec<ZirAssemblyStatement<'ast, T>>, F::Error> {
    let left = f.fold_field_expression(s.left)?;
    let right = f.fold_field_expression(s.right)?;
    Ok(vec![ZirAssemblyStatement::constraint(
        left, right, s.metadata,
    )])
}

fn fold_assembly_statement<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: ZirAssemblyStatement<'ast, T>,
) -> Result<Vec<ZirAssemblyStatement<'ast, T>>, F::Error> {
    let span = s.get_span();
    f.fold_assembly_statement_cases(s)
        .map(|s| s.into_iter().map(|s| s.span(span)).collect())
}

pub fn fold_assembly_statement_cases<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: ZirAssemblyStatement<'ast, T>,
) -> Result<Vec<ZirAssemblyStatement<'ast, T>>, F::Error> {
    match s {
        ZirAssemblyStatement::Assignment(s) => f.fold_assembly_assignment(s),
        ZirAssemblyStatement::Constraint(s) => f.fold_assembly_constraint(s),
    }
}

pub fn fold_statement<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: ZirStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    let span = s.get_span();
    f.fold_statement_cases(s)
        .map(|s| s.into_iter().map(|s| s.span(span)).collect())
}

pub fn fold_statement_cases<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: ZirStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    let span = s.get_span();

    match s {
        ZirStatement::Return(s) => f.fold_return_statement(s),
        ZirStatement::Definition(s) => f.fold_definition_statement(s),
        ZirStatement::IfElse(s) => f.fold_if_else_statement(s),
        ZirStatement::Assertion(s) => f.fold_assertion_statement(s),
        ZirStatement::MultipleDefinition(s) => f.fold_multiple_definition_statement(s),
        ZirStatement::Log(s) => f.fold_log_statement(s),
        ZirStatement::Assembly(s) => f.fold_assembly_block(s),
    }
    .map(|s| s.into_iter().map(|s| s.span(span)).collect())
}

pub fn fold_return_statement<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: ReturnStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    Ok(vec![ZirStatement::Return(
        ReturnStatement::new(
            s.inner
                .into_iter()
                .map(|e| f.fold_expression(e))
                .collect::<Result<_, _>>()?,
        )
        .span(s.span),
    )])
}

pub fn fold_definition_statement<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: DefinitionStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    let rhs = f.fold_expression(s.rhs)?;
    Ok(vec![ZirStatement::Definition(
        DefinitionStatement::new(f.fold_assignee(s.assignee)?, rhs).span(s.span),
    )])
}

pub fn fold_if_else_statement<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: IfElseStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    Ok(vec![ZirStatement::IfElse(
        IfElseStatement::new(
            f.fold_boolean_expression(s.condition)?,
            s.consequence
                .into_iter()
                .map(|s| f.fold_statement(s))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect(),
            s.alternative
                .into_iter()
                .map(|s| f.fold_statement(s))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect(),
        )
        .span(s.span),
    )])
}

pub fn fold_assertion_statement<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: AssertionStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    Ok(vec![ZirStatement::Assertion(
        AssertionStatement::new(f.fold_boolean_expression(s.expression)?, s.error).span(s.span),
    )])
}

pub fn fold_log_statement<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: LogStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    let expressions = s
        .expressions
        .into_iter()
        .map(|(t, e)| {
            e.into_iter()
                .map(|e| f.fold_expression(e))
                .collect::<Result<Vec<_>, _>>()
                .map(|e| (t, e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(vec![ZirStatement::Log(LogStatement::new(
        s.format_string,
        expressions,
    ))])
}

pub fn fold_assembly_block<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: AssemblyBlockStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    Ok(vec![ZirStatement::Assembly(AssemblyBlockStatement::new(
        s.inner
            .into_iter()
            .map(|s| f.fold_assembly_statement(s))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect(),
    ))])
}

pub fn fold_multiple_definition_statement<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    s: MultipleDefinitionStatement<'ast, T>,
) -> Result<Vec<ZirStatement<'ast, T>>, F::Error> {
    let expression_list = f.fold_expression_list(s.rhs)?;
    Ok(vec![ZirStatement::MultipleDefinition(
        MultipleDefinitionStatement::new(
            s.assignees
                .into_iter()
                .map(|v| f.fold_assignee(v))
                .collect::<Result<_, _>>()?,
            expression_list,
        ),
    )])
}

fn fold_field_expression<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    e: FieldElementExpression<'ast, T>,
) -> Result<FieldElementExpression<'ast, T>, F::Error> {
    let span = e.get_span();
    f.fold_field_expression_cases(e).map(|e| e.span(span))
}

pub fn fold_field_expression_cases<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    e: FieldElementExpression<'ast, T>,
) -> Result<FieldElementExpression<'ast, T>, F::Error> {
    Ok(match e {
        FieldElementExpression::Value(n) => FieldElementExpression::Value(n),
        FieldElementExpression::Identifier(id) => {
            match f.fold_identifier_expression(&Type::FieldElement, id)? {
                IdentifierOrExpression::Identifier(i) => FieldElementExpression::Identifier(i),
                IdentifierOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::Select(e) => {
            match f.fold_select_expression(&Type::FieldElement, e)? {
                SelectOrExpression::Select(s) => FieldElementExpression::Select(s),
                SelectOrExpression::Expression(u) => u,
            }
        }
        FieldElementExpression::Add(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::Add(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::Sub(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::Sub(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::Mult(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::Mult(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::Div(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::Div(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::Pow(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::Pow(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::And(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::And(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::Or(e) => match f.fold_binary_expression(&Type::FieldElement, e)? {
            BinaryOrExpression::Binary(e) => FieldElementExpression::Or(e),
            BinaryOrExpression::Expression(e) => e,
        },
        FieldElementExpression::Xor(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::Xor(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::LeftShift(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::LeftShift(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::RightShift(e) => {
            match f.fold_binary_expression(&Type::FieldElement, e)? {
                BinaryOrExpression::Binary(e) => FieldElementExpression::RightShift(e),
                BinaryOrExpression::Expression(e) => e,
            }
        }
        FieldElementExpression::Conditional(c) => {
            match f.fold_conditional_expression(&Type::FieldElement, c)? {
                ConditionalOrExpression::Conditional(s) => FieldElementExpression::Conditional(s),
                ConditionalOrExpression::Expression(u) => u,
            }
        }
    })
}

fn fold_boolean_expression<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    e: BooleanExpression<'ast, T>,
) -> Result<BooleanExpression<'ast, T>, F::Error> {
    let span = e.get_span();
    f.fold_boolean_expression_cases(e).map(|e| e.span(span))
}

pub fn fold_boolean_expression_cases<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    e: BooleanExpression<'ast, T>,
) -> Result<BooleanExpression<'ast, T>, F::Error> {
    use BooleanExpression::*;

    Ok(match e {
        BooleanExpression::Value(v) => BooleanExpression::Value(v),
        BooleanExpression::Identifier(id) => {
            match f.fold_identifier_expression(&Type::Boolean, id)? {
                IdentifierOrExpression::Identifier(i) => BooleanExpression::Identifier(i),
                IdentifierOrExpression::Expression(e) => e,
            }
        }
        BooleanExpression::Select(e) => match f.fold_select_expression(&Type::Boolean, e)? {
            SelectOrExpression::Select(s) => BooleanExpression::Select(s),
            SelectOrExpression::Expression(u) => u,
        },
        FieldEq(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => FieldEq(e),
            BinaryOrExpression::Expression(u) => u,
        },
        BoolEq(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => BoolEq(e),
            BinaryOrExpression::Expression(u) => u,
        },
        UintEq(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => UintEq(e),
            BinaryOrExpression::Expression(u) => u,
        },
        FieldLt(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => FieldLt(e),
            BinaryOrExpression::Expression(u) => u,
        },
        FieldLe(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => FieldLe(e),
            BinaryOrExpression::Expression(u) => u,
        },
        UintLt(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => UintLt(e),
            BinaryOrExpression::Expression(u) => u,
        },
        UintLe(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => UintLe(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Or(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => Or(e),
            BinaryOrExpression::Expression(u) => u,
        },
        And(e) => match f.fold_binary_expression(&Type::Boolean, e)? {
            BinaryOrExpression::Binary(e) => And(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Not(e) => match f.fold_unary_expression(&Type::Boolean, e)? {
            UnaryOrExpression::Unary(e) => Not(e),
            UnaryOrExpression::Expression(u) => u,
        },
        BooleanExpression::Conditional(c) => {
            match f.fold_conditional_expression(&Type::Boolean, c)? {
                ConditionalOrExpression::Conditional(s) => BooleanExpression::Conditional(s),
                ConditionalOrExpression::Expression(u) => u,
            }
        }
    })
}

pub fn fold_uint_expression<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    e: UExpression<'ast, T>,
) -> Result<UExpression<'ast, T>, F::Error> {
    Ok(UExpression {
        inner: f.fold_uint_expression_inner(e.bitwidth, e.inner)?,
        ..e
    })
}

fn fold_uint_expression_inner<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    ty: UBitwidth,
    e: UExpressionInner<'ast, T>,
) -> Result<UExpressionInner<'ast, T>, F::Error> {
    let span = e.get_span();
    f.fold_uint_expression_cases(ty, e).map(|e| e.span(span))
}

pub fn fold_uint_expression_cases<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    ty: UBitwidth,
    e: UExpressionInner<'ast, T>,
) -> Result<UExpressionInner<'ast, T>, F::Error> {
    use UExpressionInner::*;

    Ok(match e {
        Value(v) => UExpressionInner::Value(v),
        Identifier(id) => match f.fold_identifier_expression(&ty, id)? {
            IdentifierOrExpression::Identifier(i) => UExpressionInner::Identifier(i),
            IdentifierOrExpression::Expression(e) => e,
        },
        Select(e) => match f.fold_select_expression(&ty, e)? {
            SelectOrExpression::Select(s) => UExpressionInner::Select(s),
            SelectOrExpression::Expression(u) => u,
        },
        Add(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => Add(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Sub(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => Sub(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Mult(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => Mult(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Div(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => Div(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Rem(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => Rem(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Xor(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => Xor(e),
            BinaryOrExpression::Expression(u) => u,
        },
        And(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => And(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Or(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => Or(e),
            BinaryOrExpression::Expression(u) => u,
        },
        LeftShift(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => LeftShift(e),
            BinaryOrExpression::Expression(u) => u,
        },
        RightShift(e) => match f.fold_binary_expression(&ty, e)? {
            BinaryOrExpression::Binary(e) => RightShift(e),
            BinaryOrExpression::Expression(u) => u,
        },
        Not(e) => match f.fold_unary_expression(&ty, e)? {
            UnaryOrExpression::Unary(e) => Not(e),
            UnaryOrExpression::Expression(u) => u,
        },
        Conditional(c) => match f.fold_conditional_expression(&ty, c)? {
            ConditionalOrExpression::Conditional(s) => Conditional(s),
            ConditionalOrExpression::Expression(u) => u,
        },
    })
}

pub fn fold_function<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    fun: ZirFunction<'ast, T>,
) -> Result<ZirFunction<'ast, T>, F::Error> {
    Ok(ZirFunction {
        arguments: fun
            .arguments
            .into_iter()
            .map(|a| f.fold_parameter(a))
            .collect::<Result<_, _>>()?,
        statements: fun
            .statements
            .into_iter()
            .map(|s| f.fold_statement(s))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect(),
        ..fun
    })
}

pub fn fold_program<'ast, T: Field, F: ResultFolder<'ast, T>>(
    f: &mut F,
    p: ZirProgram<'ast, T>,
) -> Result<ZirProgram<'ast, T>, F::Error> {
    Ok(ZirProgram {
        main: f.fold_function(p.main)?,
        ..p
    })
}

pub fn fold_identifier_expression<
    'ast,
    T: Field,
    E: Expr<'ast, T> + Id<'ast, T>,
    F: ResultFolder<'ast, T>,
>(
    f: &mut F,
    _: &E::Ty,
    e: IdentifierExpression<'ast, E>,
) -> Result<IdentifierOrExpression<Identifier<'ast>, E, E::Inner>, F::Error> {
    Ok(IdentifierOrExpression::Identifier(
        IdentifierExpression::new(f.fold_name(e.id)?),
    ))
}

pub fn fold_conditional_expression<
    'ast,
    T: Field,
    E: Expr<'ast, T> + ResultFold<F, F::Error> + Conditional<'ast, T>,
    F: ResultFolder<'ast, T>,
>(
    f: &mut F,
    _: &E::Ty,
    e: ConditionalExpression<'ast, T, E>,
) -> Result<ConditionalOrExpression<'ast, T, E>, F::Error> {
    Ok(ConditionalOrExpression::Conditional(
        ConditionalExpression::new(
            f.fold_boolean_expression(*e.condition)?,
            e.consequence.fold(f)?,
            e.alternative.fold(f)?,
        ),
    ))
}

pub fn fold_select_expression<
    'ast,
    T: Field,
    E: Expr<'ast, T> + ResultFold<F, F::Error> + Select<'ast, T>,
    F: ResultFolder<'ast, T>,
>(
    f: &mut F,
    _: &E::Ty,
    e: SelectExpression<'ast, T, E>,
) -> Result<SelectOrExpression<'ast, T, E>, F::Error> {
    Ok(SelectOrExpression::Select(SelectExpression::new(
        e.array
            .into_iter()
            .map(|e| e.fold(f))
            .collect::<Result<Vec<_>, _>>()?,
        e.index.fold(f)?,
    )))
}

#[allow(clippy::type_complexity)]
pub fn fold_binary_expression<
    'ast,
    T: Field,
    L: Expr<'ast, T> + PartialEq + ResultFold<F, F::Error> + From<ZirExpression<'ast, T>>,
    R: Expr<'ast, T> + PartialEq + ResultFold<F, F::Error> + From<ZirExpression<'ast, T>>,
    E: Expr<'ast, T> + PartialEq + ResultFold<F, F::Error> + From<ZirExpression<'ast, T>>,
    F: ResultFolder<'ast, T>,
    Op,
>(
    f: &mut F,
    _: &E::Ty,
    e: BinaryExpression<Op, L, R, E>,
) -> Result<BinaryOrExpression<Op, L, R, E, E::Inner>, F::Error> {
    Ok(BinaryOrExpression::Binary(
        BinaryExpression::new(e.left.fold(f)?, e.right.fold(f)?).span(e.span),
    ))
}

pub fn fold_unary_expression<
    'ast,
    T: Field,
    In: Expr<'ast, T> + PartialEq + ResultFold<F, F::Error> + From<ZirExpression<'ast, T>>,
    E: Expr<'ast, T> + PartialEq + ResultFold<F, F::Error> + From<ZirExpression<'ast, T>>,
    F: ResultFolder<'ast, T>,
    Op,
>(
    f: &mut F,
    _: &E::Ty,
    e: UnaryExpression<Op, In, E>,
) -> Result<UnaryOrExpression<Op, In, E, E::Inner>, F::Error> {
    Ok(UnaryOrExpression::Unary(
        UnaryExpression::new(e.inner.fold(f)?).span(e.span),
    ))
}
