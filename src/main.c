#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  TOK_EOF,
  TOK_INT,
  TOK_RETURN,
  TOK_IF,
  TOK_ELSE,
  TOK_WHILE,
  TOK_VOID,
  TOK_IDENT,
  TOK_NUMBER,
  TOK_LPAREN,
  TOK_RPAREN,
  TOK_LBRACE,
  TOK_RBRACE,
  TOK_SEMICOLON,
  TOK_COMMA,
  TOK_ASSIGN,
  TOK_PLUS,
  TOK_MINUS,
  TOK_STAR,
  TOK_SLASH,
  TOK_PERCENT,
  TOK_LT,
  TOK_GT,
  TOK_LE,
  TOK_GE,
  TOK_EQ,
  TOK_NE,
  TOK_AND,
  TOK_OR,
  TOK_AMPERSAND,
  TOK_PIPE,
  TOK_CARET,
  TOK_LSHIFT,
  TOK_RSHIFT,
  TOK_LBRACKET,
  TOK_RBRACKET,
  TOK_STRING,
  TOK_ASM
} TokenType;

typedef struct {
  TokenType type;
  char *text;
  int value;
} Token;

typedef struct {
  char *input;
  int pos;
  Token current;
} Lexer;

typedef enum {
  NODE_PROGRAM,
  NODE_FUNCTION,
  NODE_RETURN,
  NODE_IF,
  NODE_WHILE,
  NODE_BINOP,
  NODE_NUMBER,
  NODE_VAR,
  NODE_ASSIGN,
  NODE_CALL,
  NODE_BLOCK,
  NODE_DEREF,
  NODE_ADDR,
  NODE_INDEX,
  NODE_ASM,
  NODE_GLOBAL_VAR
} NodeType;

typedef struct ASTNode {
  NodeType type;
  union {
    int number;
    char *name;
    struct {
      struct ASTNode *left;
      struct ASTNode *right;
      TokenType op;
    } binop;
    struct {
      char *name;
      struct ASTNode **params;
      int param_count;
      struct ASTNode *body;
    } function;
    struct {
      struct ASTNode *expr;
    } ret;
    struct {
      struct ASTNode *cond;
      struct ASTNode *then_branch;
      struct ASTNode *else_branch;
    } if_stmt;
    struct {
      struct ASTNode *cond;
      struct ASTNode *body;
    } while_stmt;
    struct {
      char *var;
      struct ASTNode *expr;
    } assign;
    struct {
      char *name;
      struct ASTNode **args;
      int arg_count;
    } call;
    struct {
      struct ASTNode **stmts;
      int stmt_count;
    } block;
    struct {
      struct ASTNode *expr;
    } unary;
    struct {
      struct ASTNode *array;
      struct ASTNode *index;
    } index;
    struct {
      char *code;
    } asm_code;
    struct {
      char *name;
      char *string_value;
      int int_value;
      int is_string;
    } global_var;
  };
} ASTNode;

typedef struct {
  char *name;
  int offset; /* Offset from the frame pointer */
  int is_array;
  int array_size;
} Symbol;

typedef struct {
  Symbol *symbols;
  int count;
  int capacity;
  int stack_offset;
} SymbolTable;

typedef struct {
  FILE *out;
  int label_count;
  SymbolTable symtab;
} CodeGen;

void lexer_init(Lexer *lex, char *input) {
  lex->input = input;
  lex->pos = 0;
}

void skip_whitespace(Lexer *lex) {
  while (isspace(lex->input[lex->pos])) {
    lex->pos++;
  }
}

Token lexer_next(Lexer *lex) {
  skip_whitespace(lex);
  Token tok = {0};

  if (lex->input[lex->pos] == '\0') {
    tok.type = TOK_EOF;

    return tok;
  }

  /* Identifiers and keywords */
  if (isalpha(lex->input[lex->pos]) || lex->input[lex->pos] == '_') {
    int start = lex->pos;

    while (isalnum(lex->input[lex->pos]) || lex->input[lex->pos] == '_') {
      lex->pos++;
    }

    int len = lex->pos - start;
    tok.text = malloc(len + 1);
    strncpy(tok.text, &lex->input[start], len);
    tok.text[len] = '\0';

    if (strcmp(tok.text, "int") == 0) {
      tok.type = TOK_INT;
    } else if (strcmp(tok.text, "void") == 0) {
      tok.type = TOK_VOID;
    } else if (strcmp(tok.text, "return") == 0) {
      tok.type = TOK_RETURN;
    } else if (strcmp(tok.text, "if") == 0) {
      tok.type = TOK_IF;
    } else if (strcmp(tok.text, "else") == 0) {
      tok.type = TOK_ELSE;
    } else if (strcmp(tok.text, "while") == 0) {
      tok.type = TOK_WHILE;
    } else if (strcmp(tok.text, "asm") == 0) {
      tok.type = TOK_ASM;
    } else {
      tok.type = TOK_IDENT;
    }

    return tok;
  }

  /* Numbers */
  if (isdigit(lex->input[lex->pos])) {
    tok.type = TOK_NUMBER;
    tok.value = 0;

    while (isdigit(lex->input[lex->pos])) {
      /* Cool ASCII trick to convert the character into a number :3
       * If we pass "123"
       * Read '1': tok.value = 0  * 10 + (49 - 48) = 1
       * Read '2': tok.value = 1  * 10 + (50 - 48) = 12
       * Read '3': tok.value = 12 * 10 + (51 - 48) = 123
       * */

      tok.value = tok.value * 10 + (lex->input[lex->pos] - '0');
      lex->pos++;
    }

    return tok;
  }

  /* String literals */
  if (lex->input[lex->pos] == '"') {
    lex->pos++;
    int start = lex->pos;
    while (lex->input[lex->pos] != '"' && lex->input[lex->pos] != '\0') {
      lex->pos++;
    }
    int len = lex->pos - start;
    tok.type = TOK_STRING;
    tok.text = malloc(len + 1);
    strncpy(tok.text, &lex->input[start], len);
    tok.text[len] = '\0';
    if (lex->input[lex->pos] == '"') {
      lex->pos++;
    }
    return tok;
  }

  /* Operators */
  switch (lex->input[lex->pos]) {
  case '(': {
    tok.type = TOK_LPAREN;
    lex->pos++;
  } break;
  case ')': {
    tok.type = TOK_RPAREN;
    lex->pos++;
  } break;
  case '{': {
    tok.type = TOK_LBRACE;
    lex->pos++;
  } break;
  case '}': {
    tok.type = TOK_RBRACE;
    lex->pos++;
  } break;
  case '[': {
    tok.type = TOK_LBRACKET;
    lex->pos++;
  } break;
  case ']': {
    tok.type = TOK_RBRACKET;
    lex->pos++;
  } break;
  case ';': {
    tok.type = TOK_SEMICOLON;
    lex->pos++;
  } break;
  case ',': {
    tok.type = TOK_COMMA;
    lex->pos++;
  } break;
  case '+': {
    tok.type = TOK_PLUS;
    lex->pos++;
  } break;
  case '-': {
    tok.type = TOK_MINUS;
    lex->pos++;
  } break;
  case '*': {
    tok.type = TOK_STAR;
    lex->pos++;
  } break;
  case '/': {
    tok.type = TOK_SLASH;
    lex->pos++;
  } break;
  case '%': {
    tok.type = TOK_PERCENT;
    lex->pos++;
  } break;
  case '&': {
    tok.type = TOK_AMPERSAND;
    lex->pos++;
  } break;
  case '|': {
    tok.type = TOK_PIPE;
    lex->pos++;
  } break;
  case '^': {
    tok.type = TOK_CARET;
    lex->pos++;
  } break;
  case '=': {
    lex->pos++;
    if (lex->input[lex->pos] == '=') {
      tok.type = TOK_EQ;
      lex->pos++;
    } else {
      tok.type = TOK_ASSIGN;
    }
  } break;
  case '<': {
    lex->pos++;
    if (lex->input[lex->pos] == '=') {
      tok.type = TOK_LE;
      lex->pos++;
    } else if (lex->input[lex->pos] == '<') {
      tok.type = TOK_LSHIFT;
      lex->pos++;
    } else {
      tok.type = TOK_LT;
    }
  } break;
  case '>': {
    lex->pos++;
    if (lex->input[lex->pos] == '=') {
      tok.type = TOK_GE;
      lex->pos++;
    } else if (lex->input[lex->pos] == '>') {
      tok.type = TOK_RSHIFT;
      lex->pos++;
    } else {
      tok.type = TOK_GT;
    }
  } break;
  case '!': {
    lex->pos++;
    if (lex->input[lex->pos] == '=') {
      tok.type = TOK_NE;
      lex->pos++;
    }
  } break;
  }

  return tok;
}

void symtab_init(SymbolTable *st) {
  st->symbols = NULL;
  st->count = 0;
  st->capacity = 0;
  st->stack_offset = 0;
}

int symtab_add(SymbolTable *st, char *name) {
  if (st->count >= st->capacity) {
    st->capacity = st->capacity == 0 ? 8 : st->capacity * 2;
    st->symbols = realloc(st->symbols, st->capacity * sizeof(Symbol));
  }
  st->stack_offset += 4; /* Each variable is 32-bit */
  st->symbols[st->count].name = strdup(name);
  st->symbols[st->count].offset = st->stack_offset;
  st->count++;

  return st->stack_offset;
}

int symtab_lookup(SymbolTable *st, char *name) {
  for (int i = 0; i < st->count; i++) {
    if (strcmp(st->symbols[i].name, name) == 0) {
      return i; /* Return index instead of offset. */
    }
  }

  return -1;
}

int symtab_get_offset(SymbolTable *st, int index) {
  if (index < 0 || index >= st->count) {
    return 0;
  }

  return st->symbols[index].offset;
}

void codegen_init(CodeGen *cg, FILE *out) {
  cg->out = out;
  cg->label_count = 0;
  symtab_init(&cg->symtab);
}

int new_label(CodeGen *cg) { return cg->label_count++; }

void codegen_expr(CodeGen *cg, ASTNode *node);

void codegen_binop(CodeGen *cg, ASTNode *node) {
  /* Evaluate left operand, result in r0 */
  codegen_expr(cg, node->binop.left);
  fprintf(cg->out, "\tpush r0\n");

  /* Evaluate right operand, result in r0 */
  codegen_expr(cg, node->binop.right);
  fprintf(cg->out, "\tmov r1, r0\n");
  fprintf(cg->out, "\tpop r0\n");

  /* Do the silly operation :3 */
  switch (node->binop.op) {
  case TOK_PLUS: {
    fprintf(cg->out, "\tadd r0, r1\n");
  } break;
  case TOK_MINUS: {
    fprintf(cg->out, "\tsub r0, r1\n");
  } break;
  case TOK_STAR: {
    fprintf(cg->out, "\tmul r0, r1\n");
  } break;
  case TOK_SLASH: {
    fprintf(cg->out, "\tdiv r0, r1\n");
  } break;
  case TOK_PERCENT: {
    fprintf(cg->out, "\trem r0, r1\n");
  } break;
  case TOK_AMPERSAND: {
    fprintf(cg->out, "\tand r0, r1\n");
  } break;
  case TOK_PIPE: {
    fprintf(cg->out, "\tor r0, r1\n");
  } break;
  case TOK_CARET: {
    fprintf(cg->out, "\txor r0, r1\n");
  } break;
  case TOK_LSHIFT: {
    fprintf(cg->out, "\tsla r0, r1\n");
  } break;
  case TOK_RSHIFT: {
    fprintf(cg->out, "\tsrl r0, r1\n");
  } break;
  case TOK_LT: {
    fprintf(cg->out, "\tcmp r0, r1\n");
    fprintf(cg->out, "\tmovz.8 r0, 0\n");
    fprintf(cg->out, "\tiflt mov r0, 1\n");
  } break;
  case TOK_GT: {
    fprintf(cg->out, "\tcmp r0, r1\n");
    fprintf(cg->out, "\tmovz.8 r0, 0\n");
    fprintf(cg->out, "\tifgt mov r0, 1\n");
  } break;
  case TOK_LE: {
    fprintf(cg->out, "\tcmp r0, r1\n");
    fprintf(cg->out, "\tmovz.8 r0, 0\n");
    fprintf(cg->out, "\tiflteq mov r0, 1\n");
  } break;
  case TOK_GE: {
    fprintf(cg->out, "\tcmp r0, r1\n");
    fprintf(cg->out, "\tmovz.8 r0, 0\n");
    fprintf(cg->out, "\tifgteq mov r0, 1\n");
  } break;
  case TOK_EQ: {
    fprintf(cg->out, "\tcmp r0, r1\n");
    fprintf(cg->out, "\tmovz.8 r0, 0\n");
    fprintf(cg->out, "\tifz mov r0, 1\n");
  } break;
  case TOK_NE: {
    fprintf(cg->out, "\tcmp r0, r1\n");
    fprintf(cg->out, "\tmovz.8 r0, 0\n");
    fprintf(cg->out, "\tifnz mov r0, 1\n");
  } break;
  default:
    break;
  }
}

void codegen_expr(CodeGen *cg, ASTNode *node) {
  switch (node->type) {
  case NODE_NUMBER: {
    fprintf(cg->out, "\tmov r0, %d\n", node->number);
  } break;

  case NODE_VAR: {
    int idx = symtab_lookup(&cg->symtab, node->name);
    if (idx < 0) {
      fprintf(stderr, "Undefined variable: %s\n", node->name);
      exit(1);
    }
    int offset = symtab_get_offset(&cg->symtab, idx);
    fprintf(cg->out, "\tmov r0, [rfp+%d]\n", offset);
  } break;

  case NODE_BINOP: {
    codegen_binop(cg, node);
  } break;

  case NODE_ASSIGN: {
    codegen_expr(cg, node->assign.expr);
    int idx = symtab_lookup(&cg->symtab, node->assign.var);
    int offset;
    if (idx < 0) {
      /* New local variable */
      offset = symtab_add(&cg->symtab, node->assign.var);
    } else {
      /* Existing variable (param or local) */
      offset = symtab_get_offset(&cg->symtab, idx);
    }
    fprintf(cg->out, "\tmov [rfp+%d], r0\n", offset);
  } break;

  case NODE_CALL: {
    /* fox32 calling convention (seems to be) passing arguments in r0-r7 */
    /* We need to be careful about eval order and register usage */
    if (node->call.arg_count > 8) {
      fprintf(
          stderr,
          "Warning: Function calls with >8 arguments not fully supported\n");
    }

    /* Eval all args, store on stack, then pop into registers */
    for (int i = 0; i < node->call.arg_count && i < 8; i++) {
      codegen_expr(cg, node->call.args[i]);
      fprintf(cg->out, "\tpush r0\n");
    }

    /* Pop into argument registers in reverse order */
    for (int i = (node->call.arg_count < 8 ? node->call.arg_count : 8) - 1;
         i >= 0; i--) {
      fprintf(cg->out, "\tpop r%d\n", i);
    }

    fprintf(cg->out, "\tcall %s\n", node->call.name);
    /* Result is in r0 */
  } break;
  case NODE_DEREF: {
    /* Derefence: *ptr -> load from address in ptr */
    codegen_expr(cg, node->unary.expr);
    fprintf(cg->out, "\tmov r0, [r0]\n");
  } break;
  case NODE_ADDR: {
    /* Address-of: &var -> get address of variable */
    if (node->unary.expr->type == NODE_VAR) {
      int idx = symtab_lookup(&cg->symtab, node->unary.expr->name);
      if (idx < 0) {
        fprintf(stderr, "Undefined variable: %s\n", node->unary.expr->name);
        exit(1);
      }
      int offset = symtab_get_offset(&cg->symtab, idx);
      fprintf(cg->out, "\tmov r0, rfp\n");
      fprintf(cg->out, "\tadd r0, %d\n", offset);
    } else if (node->unary.expr->type == NODE_INDEX) {
      /* &array[index] - calculate address */
      codegen_expr(cg, node->unary.expr->index.index);
      fprintf(cg->out, "\tpush r0\n");

      /* Get base address of array */
      if (node->unary.expr->index.array->type == NODE_VAR) {
        int idx =
            symtab_lookup(&cg->symtab, node->unary.expr->index.array->name);
        if (idx < 0) {
          fprintf(stderr, "Undefined array: %s\n",
                  node->unary.expr->index.array->name);
          exit(1);
        }
        int offset = symtab_get_offset(&cg->symtab, idx);
        fprintf(cg->out, "\tmov r0, rfp\n");
        fprintf(cg->out, "\tadd r0, %d\n", offset);
      }

      /* Calculate offset: index * 4 */
      fprintf(cg->out, "\tpop r1\n");
      fprintf(cg->out, "\tsla r1, 2\n");
      fprintf(cg->out, "\tadd r0, r1\n");
    } else {
      fprintf(stderr, "Cannot take address of expression\n");
      exit(1);
    }
  } break;
  case NODE_INDEX: {
    /* Array indexing: arr[index] -> load from arr + index * 4 */
    codegen_expr(cg, node->index.index);
    fprintf(cg->out, "\tpush r0\n");

    /* Get base address of array */
    if (node->index.array->type == NODE_VAR) {
      int idx = symtab_lookup(&cg->symtab, node->index.array->name);
      if (idx < 0) {
        fprintf(stderr, "Undefined array: %s\n", node->index.array->name);
        exit(1);
      }
      int offset = symtab_get_offset(&cg->symtab, idx);
      fprintf(cg->out, "\tmov r0, rfp\n");
      fprintf(cg->out, "\tadd r0, %d\n", offset);
    } else {
      /* Expression that should eval to a pointer */
      codegen_expr(cg, node->index.array);
    }

    /* Calculate offset and load */
    fprintf(cg->out, "\tpop r1\n");
    fprintf(cg->out, "\tsla r1, 2\n");
    fprintf(cg->out, "\tadd r0, r1\n");
    fprintf(cg->out, "\tmov r0, [r0]\n");
  } break;
  default:
    break;
  }
}

void codegen_stmt(CodeGen *cg, ASTNode *node) {
  switch (node->type) {
  case NODE_RETURN: {
    codegen_expr(cg, node->ret.expr);
    fprintf(cg->out, "\tmov rsp, rfp\n");
    fprintf(cg->out, "\tpop rfp\n");
    fprintf(cg->out, "\tret\n");
  } break;

  case NODE_IF: {
    int label_else = new_label(cg);
    int label_end = new_label(cg);

    codegen_expr(cg, node->if_stmt.cond);
    fprintf(cg->out, "\tcmp r0, 0\n");
    fprintf(cg->out, "\tifz rjmp .L%d\n", label_else);

    codegen_stmt(cg, node->if_stmt.then_branch);
    fprintf(cg->out, "\trjmp .L%d\n", label_end);

    fprintf(cg->out, ".L%d:\n", label_else);
    if (node->if_stmt.else_branch) {
      codegen_stmt(cg, node->if_stmt.else_branch);
    }

    fprintf(cg->out, ".L%d:\n", label_end);
  } break;

  case NODE_WHILE: {
    int label_start = new_label(cg);
    int label_end = new_label(cg);

    fprintf(cg->out, ".L%d:\n", label_start);
    codegen_expr(cg, node->while_stmt.cond);
    fprintf(cg->out, "\tcmp r0, 0\n");
    fprintf(cg->out, "\tifz rjmp .L%d\n", label_end);

    codegen_stmt(cg, node->while_stmt.body);
    fprintf(cg->out, "\trjmp .L%d\n", label_start);
    fprintf(cg->out, ".L%d:\n", label_end);
  } break;

  case NODE_BLOCK: {
    for (int i = 0; i < node->block.stmt_count; i++) {
      codegen_stmt(cg, node->block.stmts[i]);
    }
  } break;

  case NODE_ASM: {
    /* Assume the user's inline asm is correct :3 */
    fprintf(cg->out, "%s\n", node->asm_code.code);
  } break;

  default: {
    codegen_expr(cg, node);
  } break;
  }
}

void codegen_function(CodeGen *cg, ASTNode *node) {
  /* Reset symbol table for new function */
  for (int i = 0; i < cg->symtab.count; i++) {
    free(cg->symtab.symbols[i].name);
  }
  cg->symtab.count = 0;
  cg->symtab.stack_offset = 0;

  fprintf(cg->out, "%s:\n", node->function.name);
  fprintf(cg->out, "\tpush rfp\n");
  fprintf(cg->out, "\tmov rfp, rsp\n");

  /* Save registers we'll use (r0-r7 seem to be for parameters, r10-r12 for
   * temps) */
  /* We'll use r8-r9 for our temporaries to avoid conflicts */

  /* Parameters come in registers r0-r7, save them to stack and add to symbol
   * table */
  /* fox32 calling convention: args in r0, r1, r2, r3, r4, r5, r6, r7... */
  for (int i = 0; i < node->function.param_count && i < 8; i++) {
    fprintf(cg->out, "\tpush r%d\n", i);
  }

  /* Add parameters to symbol table with stack locations */
  for (int i = 0; i < node->function.param_count; i++) {
    if (cg->symtab.count >= cg->symtab.capacity) {
      cg->symtab.capacity =
          cg->symtab.capacity == 0 ? 8 : cg->symtab.capacity * 2;
      cg->symtab.symbols =
          realloc(cg->symtab.symbols, cg->symtab.capacity * sizeof(Symbol));
    }
    cg->symtab.symbols[cg->symtab.count].name =
        strdup(node->function.params[i]->name);

    /* Parameters saved on stack in reverse order (last pushed is the deepest)
     */
    /* Stack: [rfp] [r0] [r1] [r2]... so r0 is at rfp+4, r1 at rfp+8, etc. */
    cg->symtab.symbols[cg->symtab.count].offset =
        4 + (node->function.param_count - 1 - i) * 4;
    cg->symtab.count++;
  }

  /* Generate function body */
  codegen_stmt(cg, node->function.body);

  /* Ensure function has a return */
  fprintf(cg->out, "\tmov r0, 0\n");

  /* Restore stack pointer and return :3 */
  fprintf(cg->out, "\tpop rfp\n");
  fprintf(cg->out, "\tret\n\n");
}

typedef struct {
  Lexer *lex;
  Token current;
} Parser;

ASTNode *parse_statement(Parser *p);
ASTNode *parse_expression(Parser *p);

void parser_init(Parser *p, Lexer *lex) {
  p->lex = lex;
  p->current = lexer_next(lex);
}

void parser_advance(Parser *p) {
  if (p->current.text) {
    free(p->current.text);
  }
  p->current = lexer_next(p->lex);
}

int parser_check(Parser *p, TokenType type) { return p->current.type == type; }

int parser_expect(Parser *p, TokenType type) {
  if (!parser_check(p, type)) {
    fprintf(stderr, "Unexpected token at position %d\n", p->lex->pos);
    exit(1);
  }
  parser_advance(p);
  return 1;
}

ASTNode *new_node(NodeType type) {
  ASTNode *node = calloc(1, sizeof(ASTNode));
  node->type = type;
  return node;
}

ASTNode *new_number(int value) {
  ASTNode *node = new_node(NODE_NUMBER);
  node->number = value;
  return node;
}

ASTNode *new_var(char *name) {
  ASTNode *node = new_node(NODE_VAR);
  node->name = strdup(name);
  return node;
}

ASTNode *new_binop(TokenType op, ASTNode *left, ASTNode *right) {
  ASTNode *node = new_node(NODE_BINOP);
  node->binop.op = op;
  node->binop.left = left;
  node->binop.right = right;
  return node;
}

ASTNode *new_assign(char *var, ASTNode *expr) {
  ASTNode *node = new_node(NODE_ASSIGN);
  node->assign.var = strdup(var);
  node->assign.expr = expr;
  return node;
}

ASTNode *new_return(ASTNode *expr) {
  ASTNode *node = new_node(NODE_RETURN);
  node->ret.expr = expr;
  return node;
}

ASTNode *new_if(ASTNode *cond, ASTNode *then_branch, ASTNode *else_branch) {
  ASTNode *node = new_node(NODE_IF);
  node->if_stmt.cond = cond;
  node->if_stmt.then_branch = then_branch;
  node->if_stmt.else_branch = else_branch;
  return node;
}

ASTNode *new_while(ASTNode *cond, ASTNode *body) {
  ASTNode *node = new_node(NODE_WHILE);
  node->while_stmt.cond = cond;
  node->while_stmt.body = body;
  return node;
}

ASTNode *new_call(char *name, ASTNode **args, int arg_count) {
  ASTNode *node = new_node(NODE_CALL);
  node->call.name = strdup(name);
  node->call.args = args;
  node->call.arg_count = arg_count;
  return node;
}

ASTNode *new_block(ASTNode **stmts, int stmt_count) {
  ASTNode *node = new_node(NODE_BLOCK);
  node->block.stmts = stmts;
  node->block.stmt_count = stmt_count;
  return node;
}

ASTNode *new_deref(ASTNode *expr) {
  ASTNode *node = new_node(NODE_DEREF);
  node->unary.expr = expr;
  return node;
}

ASTNode *new_addr(ASTNode *expr) {
  ASTNode *node = new_node(NODE_ADDR);
  node->unary.expr = expr;
  return node;
}

ASTNode *new_index(ASTNode *array, ASTNode *index) {
  ASTNode *node = new_node(NODE_INDEX);
  node->index.array = array;
  node->index.index = index;
  return node;
}

ASTNode *new_asm(char *code) {
  ASTNode *node = new_node(NODE_ASM);
  node->asm_code.code = strdup(code);
  return node;
}

ASTNode *new_global_var(char *name, char *string_value, int int_value,
                        int is_string) {
  ASTNode *node = new_node(NODE_GLOBAL_VAR);
  node->global_var.name = strdup(name);
  node->global_var.string_value = string_value ? strdup(string_value) : NULL;
  node->global_var.int_value = int_value;
  node->global_var.is_string = is_string;
  return node;
}

ASTNode *parse_primary(Parser *p) {
  if (parser_check(p, TOK_NUMBER)) {
    int value = p->current.value;
    parser_advance(p);
    return new_number(value);
  }

  if (parser_check(p, TOK_IDENT)) {
    char *name = strdup(p->current.text);
    parser_advance(p);

    /* Function call */
    if (parser_check(p, TOK_LPAREN)) {
      parser_advance(p);

      /* Parse args */
      ASTNode **args = NULL;
      int arg_count = 0;
      int arg_cap = 0;

      if (!parser_check(p, TOK_RPAREN)) {
        while (1) {
          if (arg_count >= arg_cap) {
            arg_cap = arg_cap == 0 ? 4 : arg_cap * 2;
            args = realloc(args, arg_cap * sizeof(ASTNode *));
          }
          args[arg_count++] = parse_expression(p);

          if (!parser_check(p, TOK_COMMA)) {
            break;
          }
          parser_advance(p);
        }
      }

      parser_expect(p, TOK_RPAREN);
      return new_call(name, args, arg_count);
    }

    /* Array indexing */
    if (parser_check(p, TOK_LBRACKET)) {
      parser_advance(p);
      ASTNode *index = parse_expression(p);
      parser_expect(p, TOK_RBRACKET);
      return new_index(new_var(name), index);
    }

    /* Variable reference */
    return new_var(name);
  }

  if (parser_check(p, TOK_LPAREN)) {
    parser_advance(p);
    ASTNode *expr = parse_expression(p);
    parser_expect(p, TOK_RPAREN);
    return expr;
  }

  fprintf(stderr, "Unexpected token in expression\n");
  exit(1);
}

ASTNode *parse_unary(Parser *p) {
  if (parser_check(p, TOK_MINUS)) {
    parser_advance(p);
    ASTNode *expr = parse_unary(p);

    return new_binop(TOK_MINUS, new_number(0), expr);
  }

  if (parser_check(p, TOK_STAR)) {
    /* Dereference operator */
    parser_advance(p);
    ASTNode *expr = parse_unary(p);
    return new_deref(expr);
  }

  if (parser_check(p, TOK_AMPERSAND)) {
    /* Address-of operator */
    parser_advance(p);
    ASTNode *expr = parse_unary(p);
    return new_addr(expr);
  }

  return parse_primary(p);
}

ASTNode *parse_multiplicative(Parser *p) {
  ASTNode *left = parse_unary(p);

  while (parser_check(p, TOK_STAR) || parser_check(p, TOK_SLASH) ||
         parser_check(p, TOK_PERCENT)) {
    TokenType op = p->current.type;
    parser_advance(p);
    ASTNode *right = parse_unary(p);
    left = new_binop(op, left, right);
  }

  return left;
}

ASTNode *parse_additive(Parser *p) {
  ASTNode *left = parse_multiplicative(p);

  while (parser_check(p, TOK_PLUS) || parser_check(p, TOK_MINUS)) {
    TokenType op = p->current.type;
    parser_advance(p);
    ASTNode *right = parse_additive(p);
    left = new_binop(op, left, right);
  }

  return left;
}

ASTNode *parse_shift(Parser *p) {
  ASTNode *left = parse_additive(p);

  while (parser_check(p, TOK_LSHIFT) || parser_check(p, TOK_RSHIFT)) {
    TokenType op = p->current.type;
    parser_advance(p);
    ASTNode *right = parse_additive(p);
    left = new_binop(op, left, right);
  }

  return left;
}

ASTNode *parse_relational(Parser *p) {
  ASTNode *left = parse_shift(p);

  while (parser_check(p, TOK_LT) || parser_check(p, TOK_GT) ||
         parser_check(p, TOK_LE) || parser_check(p, TOK_GE)) {
    TokenType op = p->current.type;
    parser_advance(p);
    ASTNode *right = parse_shift(p);
    left = new_binop(op, left, right);
  }

  return left;
}

ASTNode *parse_equality(Parser *p) {
  ASTNode *left = parse_relational(p);

  while (parser_check(p, TOK_EQ) || parser_check(p, TOK_NE)) {
    TokenType op = p->current.type;
    parser_advance(p);
    ASTNode *right = parse_relational(p);
    left = new_binop(op, left, right);
  }

  return left;
}

ASTNode *parse_bitwise_and(Parser *p) {
  ASTNode *left = parse_equality(p);

  while (parser_check(p, TOK_AMPERSAND)) {
    parser_advance(p);
    ASTNode *right = parse_equality(p);
    left = new_binop(TOK_AMPERSAND, left, right);
  }

  return left;
}

ASTNode *parse_bitwise_xor(Parser *p) {
  ASTNode *left = parse_bitwise_and(p);

  while (parser_check(p, TOK_CARET)) {
    parser_advance(p);
    ASTNode *right = parse_bitwise_and(p);
    left = new_binop(TOK_CARET, left, right);
  }

  return left;
}

ASTNode *parse_bitwise_or(Parser *p) {
  ASTNode *left = parse_bitwise_xor(p);

  while (parser_check(p, TOK_PIPE)) {
    parser_advance(p);
    ASTNode *right = parse_bitwise_xor(p);
    left = new_binop(TOK_PIPE, left, right);
  }

  return left;
}

ASTNode *parse_assignment(Parser *p) {
  ASTNode *left = parse_bitwise_or(p);

  if (parser_check(p, TOK_ASSIGN)) {
    if (left->type != NODE_VAR) {
      fprintf(stderr, "Invalid assignment target\n");
      exit(1);
    }
    parser_advance(p);
    ASTNode *right = parse_assignment(p);
    return new_assign(left->name, right);
  }

  return left;
}

ASTNode *parse_expression(Parser *p) { return parse_assignment(p); }

ASTNode *parse_block(Parser *p) {
  parser_expect(p, TOK_LBRACE);

  ASTNode **stmts = NULL;
  int stmt_count = 0;
  int stmt_cap = 0;

  while (!parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF)) {
    if (stmt_count >= stmt_cap) {
      stmt_cap = stmt_cap == 0 ? 8 : stmt_cap * 2;
      stmts = realloc(stmts, stmt_cap * sizeof(ASTNode *));
    }
    stmts[stmt_count++] = parse_statement(p);
  }

  parser_expect(p, TOK_RBRACE);
  return new_block(stmts, stmt_count);
}

ASTNode *parse_statement(Parser *p) {
  /* Return statement */
  if (parser_check(p, TOK_RETURN)) {
    parser_advance(p);
    ASTNode *expr = parse_expression(p);
    parser_expect(p, TOK_SEMICOLON);
    return new_return(expr);
  }

  /* If statement */
  if (parser_check(p, TOK_IF)) {
    parser_advance(p);
    parser_expect(p, TOK_LPAREN);
    ASTNode *cond = parse_expression(p);
    parser_expect(p, TOK_RPAREN);
    ASTNode *then_branch = parse_statement(p);
    ASTNode *else_branch = NULL;

    if (parser_check(p, TOK_ELSE)) {
      parser_advance(p);
      else_branch = parse_statement(p);
    }

    return new_if(cond, then_branch, else_branch);
  }

  /* While statement */
  if (parser_check(p, TOK_WHILE)) {
    parser_advance(p);
    parser_expect(p, TOK_LPAREN);
    ASTNode *cond = parse_expression(p);
    parser_expect(p, TOK_RPAREN);
    ASTNode *body = parse_statement(p);
    return new_while(cond, body);
  }

  /* Block */
  if (parser_check(p, TOK_LBRACE)) {
    return parse_block(p);
  }

  /* Inline assembly */
  if (parser_check(p, TOK_ASM)) {
    parser_advance(p);
    parser_expect(p, TOK_LPAREN);
    if (!parser_check(p, TOK_STRING)) {
      fprintf(stderr, "Expected string literal after asm(\n");
      exit(1);
    }
    char *asm_code = strdup(p->current.text);
    parser_advance(p);
    parser_expect(p, TOK_RPAREN);
    parser_expect(p, TOK_SEMICOLON);
    return new_asm(asm_code);
  }

  /* Variable declaration */
  if (parser_check(p, TOK_INT)) {
    parser_advance(p);
    if (!parser_check(p, TOK_IDENT)) {
      fprintf(stderr, "Expected identifier after 'int'\n");
      exit(1);
    }
    char *name = strdup(p->current.text);
    parser_advance(p);

    /* Array declaration */
    if (parser_check(p, TOK_LBRACKET)) {
      parser_advance(p);
      if (!parser_check(p, TOK_NUMBER)) {
        fprintf(stderr, "Expected array size\n");
        exit(1);
      }
      int size = p->current.value;
      parser_advance(p);
      parser_expect(p, TOK_RBRACKET);
      parser_expect(p, TOK_SEMICOLON);
      /* For arrays, we just allocate space and create a dummy assignment */
      return new_assign(name, new_number(size * 4));
    }

    ASTNode *init = NULL;
    if (parser_check(p, TOK_ASSIGN)) {
      parser_advance(p);
      init = parse_expression(p);
    }

    parser_expect(p, TOK_SEMICOLON);

    if (init) {
      return new_assign(name, init);
    } else {
      /* Declaration without initialization, allocate space. */
      return new_assign(name, new_number(0));
    }
  }

  /* Expression statement */
  ASTNode *expr = parse_expression(p);
  parser_expect(p, TOK_SEMICOLON);

  return expr;
}

ASTNode *parse_function(Parser *p) {
  /* Return type */
  if (parser_check(p, TOK_VOID)) {
    parser_advance(p);
  } else if (parser_check(p, TOK_INT)) {
    parser_advance(p);
  } else {
    fprintf(stderr, "Expected return type\n");
    exit(1);
  }

  /* Function name */
  if (!parser_check(p, TOK_IDENT)) {
    fprintf(stderr, "Expected function name\n");
    exit(1);
  }

  char *name = strdup(p->current.text);
  parser_advance(p);

  /* Parameters */
  parser_expect(p, TOK_LPAREN);

  ASTNode **params = NULL;
  int param_count = 0;
  int param_cap = 0;

  if (!parser_check(p, TOK_RPAREN)) {
    while (1) {
      if (parser_check(p, TOK_VOID)) {
        /* void parameter list */
        parser_advance(p);
        break;
      }

      parser_expect(p, TOK_INT);
      if (!parser_check(p, TOK_IDENT)) {
        fprintf(stderr, "Expected parameter name\n");
        exit(1);
      }

      if (param_count >= param_cap) {
        param_cap = param_cap == 0 ? 4 : param_cap * 2;
        params = realloc(params, param_cap * sizeof(ASTNode *));
      }
      params[param_count++] = new_var(p->current.text);
      parser_advance(p);

      if (!parser_check(p, TOK_COMMA)) {
        break;
      }
      parser_advance(p);
    }
  }

  parser_expect(p, TOK_RPAREN);

  /* Function body */
  ASTNode *body = parse_block(p);

  ASTNode *func = new_node(NODE_FUNCTION);
  func->function.name = name;
  func->function.params = params;
  func->function.param_count = param_count;
  func->function.body = body;

  return func;
}

ASTNode *parse_program(Parser *p) {
  ASTNode *prog = new_node(NODE_PROGRAM);
  prog->block.stmts = NULL;
  prog->block.stmt_count = 0;
  int cap = 0;

  while (!parser_check(p, TOK_EOF)) {
    if (prog->block.stmt_count >= cap) {
      cap = cap == 0 ? 8 : cap * 2;
      prog->block.stmts = realloc(prog->block.stmts, cap * sizeof(ASTNode *));
    }

    /* Check for global variables */
    if (parser_check(p, TOK_INT) || parser_check(p, TOK_VOID)) {
      parser_advance(p);

      if (!parser_check(p, TOK_IDENT)) {
        fprintf(stderr, "Expected identifier\n");
        exit(1);
      }
      char *name = strdup(p->current.text);
      parser_advance(p);

      /* Check if this is a function (has parenthesis) */
      if (parser_check(p, TOK_LPAREN)) {
        /* This is a function, for now parse manually. */
        /* FIXME: Add support for backing up the parser so we can put this back
         * in the parse_function function. */
        ASTNode **params = NULL;
        int param_count = 0;
        int param_cap = 0;

        parser_advance(p);

        if (!parser_check(p, TOK_RPAREN)) {
          while (1) {
            if (parser_check(p, TOK_VOID)) {
              parser_advance(p);
              break;
            }

            parser_expect(p, TOK_INT);
            if (!parser_check(p, TOK_IDENT)) {
              fprintf(stderr, "Expected parameter name\n");
              exit(1);
            }

            if (param_count >= param_cap) {
              param_cap = param_cap == 0 ? 4 : param_cap * 2;
              params = realloc(params, param_cap * sizeof(ASTNode *));
            }
            params[param_count++] = new_var(p->current.text);
            parser_advance(p);

            if (!parser_check(p, TOK_COMMA)) {
              break;
            }
            parser_advance(p);
          }
        }

        parser_expect(p, TOK_RPAREN);
        ASTNode *body = parse_block(p);

        ASTNode *func = new_node(NODE_FUNCTION);
        func->function.name = name;
        func->function.params = params;
        func->function.param_count = param_count;
        func->function.body = body;

        prog->block.stmts[prog->block.stmt_count++] = func;
      } else if (parser_check(p, TOK_ASSIGN)) {
        /* Global variable with initializer */
        parser_advance(p);
        if (parser_check(p, TOK_STRING)) {
          prog->block.stmts[prog->block.stmt_count++] =
              new_global_var(name, p->current.text, 0, 1);
          parser_advance(p);
        } else if (parser_check(p, TOK_NUMBER)) {
          prog->block.stmts[prog->block.stmt_count++] =
              new_global_var(name, NULL, p->current.value, 0);
          parser_advance(p);
        }
        parser_expect(p, TOK_SEMICOLON);
      } else {
        parser_expect(p, TOK_SEMICOLON);
        prog->block.stmts[prog->block.stmt_count++] =
            new_global_var(name, NULL, 0, 0);
      }
    } else {
      /* Must be a function */
      prog->block.stmts[prog->block.stmt_count++] = parse_function(p);
    }
  }

  return prog;
}

void compile(char *source, FILE *output) {
  Lexer lex;
  lexer_init(&lex, source);

  Parser parser;
  parser_init(&parser, &lex);

  ASTNode *program = parse_program(&parser);

  CodeGen cg;
  codegen_init(&cg, output);

  fprintf(output, "; FenneC Compiler Output\n\n");

  /* Generate main first */
  for (int i = 0; i < program->block.stmt_count; i++) {
    ASTNode *func = program->block.stmts[i];
    if (func->type == NODE_FUNCTION &&
        strcmp(func->function.name, "main") == 0) {

      fprintf(output, "\t; main function\n");

      /* Reset symbol table */
      for (int j = 0; j < cg.symtab.count; j++)
        free(cg.symtab.symbols[j].name);
      cg.symtab.count = 0;
      cg.symtab.stack_offset = 0;

      fprintf(output, "\tpush rfp\n");
      fprintf(output, "\tmov rfp, rsp\n");

      /* Push up to 8 parameters */
      for (int j = 0; j < func->function.param_count && j < 8; j++) {
        fprintf(output, "\tpush r%d\n", j);
      }

      /* Add parameters to symbol table */
      for (int j = 0; j < func->function.param_count; j++) {
        if (cg.symtab.count >= cg.symtab.capacity) {
          cg.symtab.capacity =
              cg.symtab.capacity == 0 ? 8 : cg.symtab.capacity * 2;
          cg.symtab.symbols =
              realloc(cg.symtab.symbols, cg.symtab.capacity * sizeof(Symbol));
        }
        cg.symtab.symbols[cg.symtab.count].name =
            strdup(func->function.params[j]->name);
        cg.symtab.symbols[cg.symtab.count].offset =
            4 + (func->function.param_count - 1 - j) * 4;
        cg.symtab.count++;
      }

      /* Generate function body */
      codegen_stmt(&cg, func->function.body);

      fprintf(output, "\tmov r0, 0\n");
      fprintf(output, "\tpop rfp\n");
      // fprintf(output, "ret\n\n");
      break; /* main emitted, stop loop */
    }
  }

  /* Generate other functions */
  for (int i = 0; i < program->block.stmt_count; i++) {
    ASTNode *func = program->block.stmts[i];
    if (func->type == NODE_FUNCTION &&
        strcmp(func->function.name, "main") != 0) {
      codegen_function(&cg, func);
    }
  }

  /* Now we can generate the globals :3 */
  for (int i = 0; i < program->block.stmt_count; i++) {
    if (program->block.stmts[i]->type == NODE_GLOBAL_VAR) {
      ASTNode *gvar = program->block.stmts[i];
      if (gvar->global_var.is_string) {
        fprintf(output, "%s: data.strz \"%s\"\n", gvar->global_var.name,
                gvar->global_var.string_value);
      } else {
        fprintf(output, "%s: data.32 %d\n", gvar->global_var.name,
                gvar->global_var.int_value);
      }
    }
  }

  fprintf(output, "\n; Includes :3\n\n");
  fprintf(output, "#include \"../fox32rom/fox32rom.def\"\n");
  fprintf(output, "#include \"../fox32os/fox32os.def\"\n\n");
}

int main() {
  char *test_program =
      "int window_title = \"Hello fox32os!\";\n"
      "int hello_str = \"Hello from C!\";\n"
      "\n"
      "void draw_hello(int window_struct) {\n"
      "    int overlay_id;\n"
      "    \n"
      "    overlay_id = get_window_overlay_number(window_struct);\n"
      "    \n"
      "    asm(\"    mov r5, r0\");\n"
      "    asm(\"    mov r0, hello_str\");\n"
      "    asm(\"    mov r1, 32\");\n"
      "    asm(\"    mov r2, 32\");\n"
      "    asm(\"    mov r3, 0xFFFFFFFF\");\n"
      "    asm(\"    mov r4, 0xFF000000\");\n"
      "    asm(\"    call draw_str_to_overlay\");\n"
      "}\n"
      "\n"
      "int main() {\n"
      "    int window_title;\n"
      "    int window_struct[10];\n"
      "    int event_type;\n"
      "    \n"
      "    new_window(&window_struct[0], window_title, 256, 256, 64, 64, 0, "
      "0);\n"
      "    \n"
      "    draw_hello(&window_struct[0]);\n"
      "    \n"
      "    while (1) {\n"
      "        event_type = get_next_window_event(&window_struct[0]);\n"
      "        \n"
      "        if (event_type == 1) {\n"
      "            asm(\"    call end_current_task\");\n"
      "        }\n"
      "        \n"
      "        asm(\"    call yield_task\");\n"
      "    }\n"
      "    \n"
      "    return 0;\n"
      "}\n";

  char *empty_test_program = "int main() {\n"
                             "    int yeah;\n"
                             "    yeah = 4;\n"
                             "    yeah = yeah * 2;\n"
                             "    asm(\"\tcall end_current_task\");\n"
                             "}\n";

  compile(test_program, stdout);

  return EXIT_SUCCESS;
}
