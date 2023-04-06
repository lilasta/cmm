#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

typedef enum
{
	TK_EOF,
	TK_VAR,
	TK_MAIN,
	TK_PAROPEN,
	TK_PARCLOSE,
	TK_COMMA,
	TK_CURLOPEN,
	TK_CURLCLOSE,
	TK_WRITE,
	TK_WRITELN,
	TK_SEMI,
	TK_PLUS,
	TK_MINUS,
	TK_MUL,
	TK_DIV,
	TK_IF,
	TK_THEN,
	TK_ELSE,
	TK_ENDIF,
	TK_WHILE,
	TK_DO,
	TK_READ,
	TK_RETURN,
	TK_ASSIGN,
	TK_GE,
	TK_GT,
	TK_LE,
	TK_LT,
	TK_NQ,
	TK_EQ,
	TK_NUM,
	TK_IDENT,
} TokenKind;

typedef struct
{
	TokenKind kind;
	char *num;
	char *ident;
} Token;

void token_free(Token token)
{
	if (token.kind == TK_NUM)
	{
		free(token.num);
	}

	if (token.kind == TK_IDENT)
	{
		free(token.ident);
	}
}

Token eof_token(void)
{
	return (Token){
		 .kind = TK_EOF,
		 .num = NULL,
		 .ident = NULL,
	};
}

Token symbol_token(TokenKind kind)
{
	return (Token){
		 .kind = kind,
		 .num = NULL,
		 .ident = NULL,
	};
}

Token num_token(char *num, size_t len)
{
	return (Token){
		 .kind = TK_NUM,
		 .num = strndup(num, len),
		 .ident = NULL,
	};
}

Token ident_token(char *ident, size_t len)
{
	return (Token){
		 .kind = TK_IDENT,
		 .num = NULL,
		 .ident = strndup(ident, len),
	};
}

void panic(const char *const err)
{
	fprintf(stderr, "%s\n", err);
	exit(1);
}

bool is_eof(char **src)
{
	return **src == '\0';
}

bool is_whitespace(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

bool is_numeric(char c)
{
	assert('0' < '9');
	return '0' <= c && c <= '9';
}

bool is_alphabet(char c)
{
	assert('A' < 'Z');
	assert('a' < 'z');
	return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z');
}

bool is_alphabet_or_numeric(char c)
{
	return is_alphabet(c) || is_numeric(c);
}

void skip_whitespace(char **src)
{
	while (is_whitespace(**src))
	{
		*src += 1;
	}
}

Token tokenize(char **src)
{
	skip_whitespace(src);

	if (is_eof(src))
	{
		return eof_token();
	}

	// 文字がかぶっているやつは長い方を先に書く（解析順序の問題）
	struct LexToTok
	{
		const char *const lexeme;
		TokenKind kind;
	} lextotok[29] = {
		 {"var", TK_VAR},
		 {"main", TK_MAIN},
		 {"(", TK_PAROPEN},
		 {")", TK_PARCLOSE},
		 {",", TK_COMMA},
		 {"{", TK_CURLOPEN},
		 {"}", TK_CURLCLOSE},
		 {"writeln", TK_WRITELN},
		 {"write", TK_WRITE},
		 {";", TK_SEMI},
		 {"+", TK_PLUS},
		 {"-", TK_MINUS},
		 {"*", TK_MUL},
		 {"/", TK_DIV},
		 {"if", TK_IF},
		 {"then", TK_THEN},
		 {"else", TK_ELSE},
		 {"endif", TK_ENDIF},
		 {"while", TK_WHILE},
		 {"do", TK_DO},
		 {"read", TK_READ},
		 {"return", TK_RETURN},
		 {":=", TK_ASSIGN},
		 {">=", TK_GE},
		 {">", TK_GT},
		 {"<=", TK_LE},
		 {"<", TK_LT},
		 {"!=", TK_NQ},
		 {"==", TK_EQ},
	};

	for (size_t i = 0; i < sizeof(lextotok) / sizeof(struct LexToTok); ++i)
	{
		const char *const lexeme = lextotok[i].lexeme;
		if (strncmp(*src, lexeme, strlen(lexeme)) == 0)
		{
			*src += strlen(lexeme);
			return symbol_token(lextotok[i].kind);
		}
	}

	size_t num_len = 0;
	while (is_numeric((*src)[num_len]))
	{
		num_len += 1;
	}
	if (num_len > 0)
	{
		Token num = num_token(*src, num_len);
		*src += num_len;
		return num;
	}

	size_t ident_len = 0;
	while (is_alphabet_or_numeric((*src)[ident_len]))
	{
		ident_len += 1;
	}
	if (ident_len > 0)
	{
		Token ident = ident_token(*src, ident_len);
		*src += ident_len;
		return ident;
	}

	fprintf(stderr, "AT: %s ", *src);
	panic("Unknown token");
	return eof_token();
}

bool consume(char **src, Token *token, TokenKind kind)
{
	char *src_dummy = *src;

	*token = tokenize(&src_dummy);
	if (token->kind == kind)
	{
		*src = src_dummy;
		return true;
	}
	else
	{
		token->kind = TK_EOF;
		return false;
	}
}

Token consume_exact(char **src, TokenKind kind)
{
	Token tok;
	if (!consume(src, &tok, kind))
	{
		fprintf(stderr, "AT: %s ", *src);
		panic("failed to consume token");
		return eof_token();
	}
	return tok;
}

bool eat(char **src, TokenKind kind)
{
	Token tok;
	bool ret = consume(src, &tok, kind);
	token_free(tok);
	return ret;
}

void eat_exact(char **src, TokenKind kind)
{
	token_free(consume_exact(src, kind));
}

typedef struct
{
	char **idents;
	size_t len;
} IdentTable;

IdentTable ident_table_new(void)
{
	return (IdentTable){
		 .idents = (char **)malloc(0),
		 .len = 0,
	};
}

void ident_table_free(IdentTable table)
{
	for (size_t i = 0; i < table.len; ++i)
	{
		free(table.idents[i]);
	}
	free(table.idents);
}

void ident_table_clear(IdentTable *table)
{
	ident_table_free(*table);
	*table = ident_table_new();
}

IdentTable ident_table_clone(IdentTable *table)
{
	size_t size = sizeof(char *) * table->len;
	char **cloned_idents = (char **)malloc(size);
	memcpy(cloned_idents, table->idents, size);

	return (IdentTable){
		 .idents = cloned_idents,
		 .len = table->len,
	};
}

IdentTable ident_table_merge(IdentTable table1, IdentTable table2)
{
	table1.len += table2.len;
	table1.idents = (char **)realloc(table1.idents, sizeof(char *) * table1.len);
	memcpy(table1.idents + table1.len - table2.len, table2.idents, sizeof(char *) * table2.len);
	return table1;
}

void add_ident(IdentTable *table, char *ident)
{
	table->len += 1;
	table->idents = (char **)realloc(table->idents, sizeof(char *) * table->len);
	table->idents[table->len - 1] = strdup(ident);
}

char *get_ident(IdentTable *table, size_t index)
{
	assert(index < table->len);
	return table->idents[index];
}

int get_ident_index(IdentTable *table, char *ident)
{
	for (size_t i = 0; i < table->len; ++i)
	{
		size_t rev = table->len - i - 1; // Allows shadowing
		if (strcmp(table->idents[rev], ident) == 0)
		{
			return (int)rev;
		}
	}
	return -1;
}

void codegen_jump(FILE *fp, size_t to)
{
	fprintf(fp, "(JMP, 0, %lu)\n", to);
}

void codegen_label(FILE *fp, size_t id)
{
	fprintf(fp, "(LAB, 0, %lu)\n", id);
}

void codegen_literal(FILE *fp, char *num)
{
	fprintf(fp, "(LIT, 0, %s)\n", num);
}

void codegen_add(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 2)\n");
}

void codegen_sub(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 3)\n");
}

void codegen_mul(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 4)\n");
}

void codegen_div(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 5)\n");
}

void codegen_eq(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 8)\n");
}

void codegen_neq(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 9)\n");
}

void codegen_lesser(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 10)\n");
}

void codegen_greater_eq(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 11)\n");
}

void codegen_greater(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 12)\n");
}

void codegen_lesser_eq(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 13)\n");
}

void codegen_call(FILE *fp, size_t label)
{
	fprintf(fp, "(CAL, 0, %lu)\n", label);
}

void codegen_load(FILE *fp, int index)
{
	fprintf(fp, "(LOD, 0, %d)\n", index);
}

void codegen_store(FILE *fp, int index)
{
	fprintf(fp, "(STO, 0, %d)\n", index);
}

void codegen_jump_if_zero(FILE *fp, size_t label)
{
	fprintf(fp, "(JPC, 0, %lu)\n", label);
}

void codegen_read(FILE *fp)
{
	fprintf(fp, "(CSP, 0, 0)\n");
}

void codegen_write(FILE *fp)
{
	fprintf(fp, "(CSP, 0, 1)\n");
}

void codegen_writeln(FILE *fp)
{
	fprintf(fp, "(CSP, 0, 2)\n");
}

void codegen_return(FILE *fp, size_t arg_count)
{
	fprintf(fp, "(RET, 0, %lu)\n", arg_count);
}

void codegen_allocate(FILE *fp, size_t size)
{
	fprintf(fp, "(INT, 0, %lu)\n", size);
}

void codegen_end(FILE *fp)
{
	fprintf(fp, "(OPR, 0, 0)\n");
}

typedef struct
{
	char *src;
	FILE *output;
	IdentTable funcs;
	IdentTable vars;
	size_t label_id;
	size_t arg_count;
} ParseCx;

ParseCx parse_cx_new(FILE *output, char *src)
{
	return (ParseCx){
		 .src = src,
		 .output = output,
		 .funcs = ident_table_new(),
		 .vars = ident_table_new(),
		 .arg_count = 0,
	};
}

void parse_cx_free(ParseCx cx)
{
	ident_table_free(cx.funcs);
	ident_table_free(cx.vars);
}

size_t function_label(ParseCx *cx, char *ident)
{
	int label = get_ident_index(&cx->funcs, ident);
	if (label == -1)
	{
		panic("Unknown function");
	}
	return (size_t)(label + 1) * 2;
}

size_t create_jump_label(ParseCx *cx)
{
	size_t id = cx->label_id;
	cx->label_id += 1;
	return id * 2 + 1;
}

size_t variable_index(ParseCx *cx, char *ident)
{
	int index = get_ident_index(&cx->vars, ident);
	if (index == -1)
	{
		panic("Unknown variable");
	}
	return (size_t)index + 3;
}

void parse_functions(ParseCx *);
bool parse_function(ParseCx *);
IdentTable parse_params(ParseCx *);
bool parse_body(ParseCx *);
void parse_declarations(ParseCx *);
bool parse_declaration(ParseCx *);
IdentTable parse_idents(char **src);
void parse_statements(ParseCx *);
bool parse_statement(ParseCx *);
bool parse_statement_if(ParseCx *);
bool parse_statement_while(ParseCx *);
bool parse_condition(ParseCx *);
bool parse_expression(ParseCx *);
bool parse_expression_weak(ParseCx *);
bool parse_expression_strong(ParseCx *);
bool parse_expression_term(ParseCx *);
void parse_arguments(ParseCx *);
bool parse_argument(ParseCx *);
void parse_main(ParseCx *);

void parse(ParseCx *cx)
{
	codegen_jump(cx->output, 0);

	parse_functions(cx);
	parse_main(cx);
}

void parse_functions(ParseCx *cx)
{
	while (parse_function(cx))
	{
	}
}

bool parse_function(ParseCx *cx)
{
	Token ident;
	if (!consume(&cx->src, &ident, TK_IDENT))
	{
		return false;
	}

	if (get_ident_index(&cx->funcs, ident.ident) != -1)
	{
		token_free(ident);
		panic("duplicate function name");
		return false;
	}
	else
	{
		add_ident(&cx->funcs, ident.ident);
		codegen_label(cx->output, function_label(cx, ident.ident));
	}

	consume_exact(&cx->src, TK_PAROPEN);
	IdentTable params = parse_idents(&cx->src);
	consume_exact(&cx->src, TK_PARCLOSE);

	codegen_allocate(cx->output, params.len + 3);
	cx->arg_count = params.len;
	for (size_t i = 0; i < params.len; ++i)
	{
		add_ident(&cx->vars, params.idents[i]);
		codegen_load(cx->output, -(int)(i + 1));
		codegen_store(cx->output, 3 + (int)i);
	}
	ident_table_free(params);

	parse_body(cx);
	ident_table_clear(&cx->vars);
	return true;
}

bool parse_body(ParseCx *cx)
{
	if (eat(&cx->src, TK_CURLOPEN))
	{
		size_t allocated = cx->vars.len;
		parse_declarations(cx);
		size_t allocate_size = cx->vars.len - allocated;

		if (allocate_size > 0)
		{
			codegen_allocate(cx->output, allocate_size);
		}

		parse_statements(cx);
		eat_exact(&cx->src, TK_CURLCLOSE);
		return true;
	}
	return false;
}

void parse_declarations(ParseCx *cx)
{
	while (parse_declaration(cx))
	{
	}
}

bool parse_declaration(ParseCx *cx)
{
	if (eat(&cx->src, TK_VAR))
	{
		IdentTable idents = parse_idents(&cx->src);
		if (idents.len == 0)
		{
			panic("expected variable name");
		}
		cx->vars = ident_table_merge(cx->vars, idents);
		eat_exact(&cx->src, TK_SEMI);
		return true;
	}
	else
	{
		return false;
	}
}

IdentTable parse_idents(char **src)
{
	IdentTable idents = ident_table_new();

	do
	{
		Token ident = consume_exact(src, TK_IDENT);
		add_ident(&idents, ident.ident);
		token_free(ident);
	} while (eat(src, TK_COMMA));

	return idents;
}

void parse_statements(ParseCx *cx)
{
	while (parse_statement(cx))
	{
	}
}

bool parse_statement(ParseCx *cx)
{
	if (eat(&cx->src, TK_WRITE))
	{
		parse_expression(cx);
		eat_exact(&cx->src, TK_SEMI);
		codegen_write(cx->output);
		return true;
	}

	if (eat(&cx->src, TK_WRITELN))
	{
		eat_exact(&cx->src, TK_SEMI);
		codegen_writeln(cx->output);
		return true;
	}

	if (eat(&cx->src, TK_READ))
	{
		Token ident = consume_exact(&cx->src, TK_IDENT);
		eat_exact(&cx->src, TK_SEMI);
		codegen_read(cx->output);
		codegen_store(cx->output, (int)variable_index(cx, ident.ident));
		token_free(ident);
		return true;
	}

	Token ident;
	if (consume(&cx->src, &ident, TK_IDENT))
	{
		eat_exact(&cx->src, TK_ASSIGN);
		parse_expression(cx);
		eat_exact(&cx->src, TK_SEMI);
		codegen_store(cx->output, (int)variable_index(cx, ident.ident));
		token_free(ident);
		return true;
	}

	if (parse_statement_if(cx))
	{
		return true;
	}

	if (parse_statement_while(cx))
	{
		return true;
	}

	if (parse_body(cx))
	{
		return true;
	}

	if (eat(&cx->src, TK_RETURN))
	{
		parse_expression(cx);
		eat_exact(&cx->src, TK_SEMI);
		codegen_return(cx->output, cx->arg_count);
		return true;
	}

	return false;
}

bool parse_statement_if(ParseCx *cx)
{
	if (eat(&cx->src, TK_IF))
	{
		size_t else_label = create_jump_label(cx);
		size_t end_label = create_jump_label(cx);

		parse_condition(cx);
		codegen_jump_if_zero(cx->output, else_label);
		eat_exact(&cx->src, TK_THEN);
		parse_statement(cx);
		codegen_jump(cx->output, end_label);

		codegen_label(cx->output, else_label);
		if (eat(&cx->src, TK_ELSE))
		{
			parse_statement(cx);
			codegen_jump(cx->output, end_label);
		}

		eat_exact(&cx->src, TK_ENDIF);
		eat_exact(&cx->src, TK_SEMI);
		codegen_label(cx->output, end_label);
		return true;
	}
	return false;
}

bool parse_statement_while(ParseCx *cx)
{
	if (!eat(&cx->src, TK_WHILE))
	{
		return false;
	}

	size_t start_label = create_jump_label(cx);
	size_t end_label = create_jump_label(cx);
	codegen_label(cx->output, start_label);
	parse_condition(cx);
	codegen_jump_if_zero(cx->output, end_label);
	eat_exact(&cx->src, TK_DO);
	parse_statement(cx);
	codegen_jump(cx->output, start_label);
	codegen_label(cx->output, end_label);
	return true;
}

bool parse_condition(ParseCx *cx)
{
	if (!parse_expression(cx))
	{
		return false;
	}

	if (eat(&cx->src, TK_GT))
	{
		assert(parse_expression(cx));
		codegen_greater(cx->output);
		return true;
	}

	if (eat(&cx->src, TK_GE))
	{
		assert(parse_expression(cx));
		codegen_greater_eq(cx->output);
		return true;
	}

	if (eat(&cx->src, TK_LT))
	{
		assert(parse_expression(cx));
		codegen_lesser(cx->output);
		return true;
	}

	if (eat(&cx->src, TK_LE))
	{
		assert(parse_expression(cx));
		codegen_lesser_eq(cx->output);
		return true;
	}

	if (eat(&cx->src, TK_NQ))
	{
		assert(parse_expression(cx));
		codegen_neq(cx->output);
		return true;
	}

	if (eat(&cx->src, TK_EQ))
	{
		assert(parse_expression(cx));
		codegen_eq(cx->output);
		return true;
	}

	panic("");
	return false;
}

bool parse_expression(ParseCx *cx)
{
	return parse_expression_weak(cx);
}

bool parse_expression_weak(ParseCx *cx)
{
	if (!parse_expression_strong(cx))
	{
		return false;
	}

	while (true)
	{
		if (eat(&cx->src, TK_PLUS))
		{
			assert(parse_expression_strong(cx));
			codegen_add(cx->output);
			continue;
		}

		if (eat(&cx->src, TK_MINUS))
		{
			assert(parse_expression_strong(cx));
			codegen_sub(cx->output);
			continue;
		}

		break;
	}

	return true;
}

bool parse_expression_strong(ParseCx *cx)
{
	if (!parse_expression_term(cx))
	{
		return false;
	}

	while (true)
	{
		if (eat(&cx->src, TK_MUL))
		{
			assert(parse_expression_term(cx));
			codegen_mul(cx->output);
			continue;
		}

		if (eat(&cx->src, TK_DIV))
		{
			assert(parse_expression_term(cx));
			codegen_div(cx->output);
			continue;
		}

		break;
	}

	return true;
}

bool parse_expression_term(ParseCx *cx)
{
	Token tok;
	if (consume(&cx->src, &tok, TK_IDENT))
	{
		if (eat(&cx->src, TK_PAROPEN))
		{
			parse_arguments(cx);
			eat_exact(&cx->src, TK_PARCLOSE);
			codegen_call(cx->output, function_label(cx, tok.ident));
		}
		else
		{
			codegen_load(cx->output, (int)variable_index(cx, tok.ident));
		}
		token_free(tok);
		return true;
	}

	if (consume(&cx->src, &tok, TK_NUM))
	{
		codegen_literal(cx->output, tok.num);
		token_free(tok);
		return true;
	}

	{
		eat_exact(&cx->src, TK_PAROPEN);
		bool ret = parse_expression(cx);
		eat_exact(&cx->src, TK_PARCLOSE);
		return ret;
	}
}

void parse_arguments(ParseCx *cx)
{
	while (parse_argument(cx))
	{
		if (!eat(&cx->src, TK_COMMA))
		{
			break;
		}
	}
}

bool parse_argument(ParseCx *cx)
{
	return parse_expression(cx);
}

void parse_main(ParseCx *cx)
{
	cx->arg_count = 0;
	codegen_label(cx->output, 0); // 0 is reserved for main
	codegen_allocate(cx->output, 3);

	eat_exact(&cx->src, TK_MAIN);
	parse_body(cx);
	codegen_end(cx->output);
}

size_t file_length(FILE *fp)
{
	fseek(fp, 0, SEEK_END);
	size_t length = (size_t)ftell(fp);
	fseek(fp, 0, SEEK_SET);
	return length;
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("Usage: %s <filename>\n", argv[0]);
		return 1;
	}

	FILE *fp = fopen(argv[1], "r");
	if (fp == NULL)
	{
		printf("Error: cannot open file %s\n", argv[1]);
		return 1;
	}

	size_t len = file_length(fp);
	char *src = malloc(sizeof(char) * len);
	fread(src, sizeof(char), len, fp);
	fclose(fp);

	ParseCx cx = parse_cx_new(stdout, src);
	parse(&cx);
	parse_cx_free(cx);
	free(src);
	return 0;
}
