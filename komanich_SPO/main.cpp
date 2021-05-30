#include <QCoreApplication>
#include <QRegularExpression>
#include <QVector>
#include <QStack>
#include <QMap>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <optional>
#include <regex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

enum class TokenKind
{
    FOR,
    WHILE,
    IF,
    ELSE,
    INCR,
    DECR,
    L_BR,       // (
    R_BR,       // )
    L_CUR,      // {
    R_CUR,      // }
    SMCLN,      // ;
    OP,         // +-/*<>|&!
    VAR,        // a-zA-Z0-9
    ASSIGN_OP,  // =
    COMMA,      // ,
    NOT_EQUAL,  // !=
    SPACE,
    STR,
    NUMBER,     // [0-9]+
    NEW,
    END_OF_FILE,
};

#define __OUT_ENUM(kind)                                                  \
    case TokenKind::kind: {                                               \
        return out << "" << #kind;                                        \
    }

std::ostream& operator<<(std::ostream& out, const TokenKind kind) {
    switch (kind) {
        __OUT_ENUM(FOR);
        __OUT_ENUM(WHILE);
        __OUT_ENUM(IF);
        __OUT_ENUM(ELSE);
        __OUT_ENUM(INCR);
        __OUT_ENUM(DECR);
        __OUT_ENUM(L_BR);
        __OUT_ENUM(R_BR);
        __OUT_ENUM(L_CUR);
        __OUT_ENUM(R_CUR);
        __OUT_ENUM(SMCLN);
        __OUT_ENUM(OP);
        __OUT_ENUM(VAR);
        __OUT_ENUM(ASSIGN_OP);
        __OUT_ENUM(COMMA);
        __OUT_ENUM(NOT_EQUAL);
        __OUT_ENUM(SPACE);
        __OUT_ENUM(STR);
        __OUT_ENUM(NUMBER);
        __OUT_ENUM(NEW);
        __OUT_ENUM(END_OF_FILE);
    }
}

struct Lexem {
    TokenKind          kind;
    QRegularExpression reg;
    int                priority;
    bool               skipable;
};


struct Token {
    TokenKind kind;
    QString   value;
};

struct MatchResult {
    Lexem   pattern;
    QString match;
};

QVector<Token> lexer(QString S, bool printLex) {
    int            startpos = 0;
    QVector<Token> tokens;

    std::vector<Lexem> Lexems{
        {TokenKind::FOR, QRegularExpression("for"), 1, false},
        {TokenKind::WHILE, QRegularExpression("while"), 1, false},
        {TokenKind::IF, QRegularExpression("if"), 1, false},
        {TokenKind::ELSE, QRegularExpression("else"), 1, false},
        {TokenKind::INCR, QRegularExpression("\\+\\+"), 0, false},
        {TokenKind::DECR, QRegularExpression("\\-\\-"), 0, false},
        {TokenKind::L_BR, QRegularExpression("\\("), 0, false},
        {TokenKind::R_BR, QRegularExpression("\\)"), 0, false},
        {TokenKind::L_CUR, QRegularExpression("\\{"), 0, false},
        {TokenKind::R_CUR, QRegularExpression("\\}"), 0, false},
        {TokenKind::SMCLN, QRegularExpression("\\;"), 0, false},
        {TokenKind::OP, QRegularExpression("[+-/*<>|&!]+"), 0, false},
        {TokenKind::OP, QRegularExpression("=="), 3, false},
        {TokenKind::VAR, QRegularExpression("[a-zA-Z][a-zA-Z0-9]*"), 0, false},
        {TokenKind::ASSIGN_OP, QRegularExpression("="), 2, false},
        {TokenKind::COMMA, QRegularExpression(","), 1, false},
        {TokenKind::NOT_EQUAL, QRegularExpression("!="), 0, false},
        {TokenKind::SPACE, QRegularExpression("\\s+"), 0, true},
        {TokenKind::STR, QRegularExpression("\".*?\""), 0, false},
        {TokenKind::NEW, QRegularExpression("new"), 1, false},
        {TokenKind::NUMBER, QRegularExpression("[0-9.]+"), 0, false},
    };

    while (startpos < S.length()) {
        QVector<MatchResult> matches;
        for (const auto& pattern : Lexems) {
            QRegularExpressionMatch match = pattern.reg.match(S, startpos);
            if (match.hasMatch()) {
                int pos = match.capturedStart(0);
                if (pos == startpos) {
                    auto len   = match.capturedLength();
                    auto found = S.mid(startpos, len);
                    matches.push_back({pattern, found});
                }
            }
        }

        std::sort(
            matches.begin(),
            matches.end(),
            [](const MatchResult& left, const MatchResult& right) {
                return left.pattern.priority > right.pattern.priority;
            });

        if (matches.size() == 0) {
            std::cerr << "No pattern matching for token at position "
                      << S[startpos].toLatin1() << "\n";
            abort();

        } else {
            const MatchResult& best = matches[0];
            if (!best.pattern.skipable) {
                tokens.push_back({best.pattern.kind, best.match});
            }
            startpos += best.match.length();
        }
    }

    if (printLex) {
        for (const auto& k : tokens) {
            std::cout << "| " << k.kind << " |"
                      << "    [ " << k.value.toStdString() << " ]"
                      << std::endl;
        }
    }
    return tokens;
}

std::ostream& operator<<(std::ostream& out, const Token match) {
    return out << "[" << match.kind << " " << match.value.toStdString()
               << "]";
}

enum class AstKind
{
    lang,
    expr,
    stmt,
    value,
    OP,
    assign_stmt,
    VAR,
    NUMBER,
    STR,
    if_stmt,
    else_body,
    while_stmt,
    while_body,
    new_expr,
    func_call,
    stmt_list
};

#define __OUT_ENUM_AST(kind)                                              \
    case AstKind::kind: {                                                 \
        return out << "" << #kind << ": ";                                \
    }

std::ostream& operator<<(std::ostream& out, const AstKind kind) {
    switch (kind) {
        __OUT_ENUM_AST(expr);
        __OUT_ENUM_AST(value);
        __OUT_ENUM_AST(OP);
        __OUT_ENUM_AST(STR);
        __OUT_ENUM_AST(VAR);
        __OUT_ENUM_AST(NUMBER);
        __OUT_ENUM_AST(stmt);
        __OUT_ENUM_AST(assign_stmt);
        __OUT_ENUM_AST(lang);
        __OUT_ENUM_AST(if_stmt);
        __OUT_ENUM_AST(else_body);
        __OUT_ENUM_AST(while_stmt);
        __OUT_ENUM_AST(while_body);
        __OUT_ENUM_AST(new_expr);
        __OUT_ENUM_AST(func_call);
        __OUT_ENUM_AST(stmt_list);
    }
}

class Ast
{
  public:
    AstKind       kind;
    QString       str;
    QVector<Ast*> subnodes;
    Ast(AstKind _kind, std::initializer_list<Ast*> _subnodes)
        : kind(_kind), subnodes(_subnodes) {
    }
    Ast(AstKind                     _kind,
        QString                     _value,
        std::initializer_list<Ast*> _subnodes)
        : kind(_kind), str(_value), subnodes(_subnodes) {
    }
    Ast(AstKind _kind, QString _str) : kind(_kind), str(_str) {
    }
    ~Ast() {
    }

    void print(int level) {
        std::cout << std::string(level * 2, ' ') << this->kind
                  << this->str.toStdString() << "\n";
        for (auto node : subnodes) {
            node->print(level + 1);
        }
    }

    void push_back(Ast* other) {
        this->subnodes.push_back(other);
    }

    Ast* operator[](int idx) {
        return this->subnodes[idx];
    }
};

class Parser
{
    QVector<Token> tokens;

    Token currentToken(int offset = 0);
    Token match(TokenKind kind);

    Ast* expr();
    Ast* value();
    Ast* stmt();
    Ast* assign_stmt();
    Ast* lang();
    Ast* if_stmt();
    Ast* while_stmt();
    Ast* new_expr();
    Ast* func_call();
    Ast* stmt_list();
    bool ok(TokenKind kind);
    void next();

  public:
    int  position = 0;
    Ast* parse();
    Parser(QVector<Token> _tokens) : tokens(_tokens) {
    }
    Ast* lhs;
    Ast* rhs;
};

void Parser::next() {
    this->position++;
}

Ast* Parser::parse() {
    return lang();
}

bool Parser::ok(TokenKind kind) {
    return currentToken().kind == kind;
}

Token Parser::currentToken(int offset) {
    if (position + offset >= tokens.size()) {
        return {TokenKind::END_OF_FILE, ""};
    } else {
        return this->tokens[this->position + offset];
    }
}

Token Parser::match(TokenKind kind) {
    if (tokens[this->position].kind == kind) {
        auto res = currentToken();
        this->position++;
        return res;
    } else {
        std::cerr << "Token at position " << position
                  << " does not match: expected " << kind << " but got "
                  << tokens[this->position].kind << std::endl;
        throw "Token doesn't match";
    }
}

Ast* Parser::lang() {
    auto ast = new Ast(AstKind::lang, {});
    ast->push_back(stmt());
    while (ok(TokenKind::VAR) || ok(TokenKind::IF)
           || ok(TokenKind::WHILE) || ok(TokenKind::FOR)
           || ok(TokenKind::NUMBER) || ok(TokenKind::OP)
           || ok(TokenKind::L_BR)) {
        ast->push_back(stmt());
    }
    return ast;
}

Ast* Parser::assign_stmt() {
    auto ast = new Ast(AstKind::assign_stmt, {});
    ast->push_back(new Ast(AstKind::VAR, match(TokenKind::VAR).value));
    match(TokenKind::ASSIGN_OP);
    if (currentToken(+1).kind == TokenKind::L_BR) {
        ast->push_back(func_call());
    } else {
        ast->push_back(expr());
        match(TokenKind::SMCLN);
    }
    return ast;
}

Ast* Parser::if_stmt() {
    auto ast = new Ast(AstKind::if_stmt, {});
    match(TokenKind::IF);
    ast->push_back(expr());
    ast->push_back(stmt_list());
    if (ok(TokenKind::ELSE)) {
        match(TokenKind::ELSE);
        ast->push_back(stmt_list());
    }
    return ast;
}

Ast* Parser::stmt_list() {
    auto list = new Ast(AstKind::stmt_list, {});
    match(TokenKind::L_CUR);
    while (ok(TokenKind::IF) || ok(TokenKind::WHILE)
           || ok(TokenKind::FOR) || ok(TokenKind::NUMBER)
           || ok(TokenKind::VAR) || ok(TokenKind::OP)
           || ok(TokenKind::L_BR)) {
        list->push_back(stmt());
    }
    match(TokenKind::R_CUR);
    return list;
}


Ast* Parser::while_stmt() {
    match(TokenKind::WHILE);
    return new Ast(AstKind::while_stmt, {expr(), stmt_list()});
}

Ast* Parser::new_expr() {
    auto ast = new Ast(AstKind::new_expr, {});
    match(TokenKind::NEW);
    match(TokenKind::VAR);
    return ast;
}

Ast* Parser::func_call() {
    auto ast = new Ast(AstKind::func_call, currentToken().value, {});
    next();
    match(TokenKind::L_BR);
    while (ok(TokenKind::NUMBER) || ok(TokenKind::VAR)
           || ok(TokenKind::L_BR) || ok(TokenKind::STR)) {
        ast->push_back(expr());
        if (ok(TokenKind::COMMA)) {
            match(TokenKind::COMMA);
        } else {
            break;
        }
    }
    match(TokenKind::R_BR);
    match(TokenKind::SMCLN);
    return ast;
}

Ast* Parser::value() {
    switch (currentToken().kind) {
        case TokenKind::VAR:
            return new Ast(AstKind::VAR, match(TokenKind::VAR).value);
        case TokenKind::NUMBER:
            return new Ast(
                AstKind::NUMBER, match(TokenKind::NUMBER).value);
        default: throw "Error. This isn't a value";
    }
}

Ast* Parser::expr() {
    if (currentToken().kind == TokenKind::NEW) {
        next();
        auto result = new Ast(AstKind::new_expr, currentToken().value);
        next();
        return result;
    }

    QVector<Token> exprTokens;
    if (currentToken().kind == TokenKind::L_BR) {
        exprTokens.push_back(currentToken());
        next();
        int balance = 1;
        while (balance > 0) {
            switch (currentToken().kind) {
                case TokenKind::L_BR: {
                    ++balance;
                    break;
                }
                case TokenKind::R_BR: {
                    --balance;
                    break;
                }
                default: break;
            }

            exprTokens.push_back(currentToken());
            next();
        }
    } else {
        while (
            !(ok(TokenKind::SMCLN) || ok(TokenKind::COMMA)
              || ok(TokenKind::R_BR))) {
            exprTokens.push_back(currentToken());
            next();
        }
    }

    std::map<QString, int> prec;
    prec["+"] = 2;
    prec["*"] = 1;
    prec["/"] = 1;
    prec["-"] = 2;
    QVector<Token> stack;
    QVector<Token> stack_res;
    QVector<Ast*>  evalStack;

    for (const auto& token : exprTokens) {
        switch (token.kind) {
            case TokenKind::OP: {
                while (!stack.empty()) {
                    if (prec[token.value] > prec[stack.back().value]) {
                        if (stack.back().kind != TokenKind::L_BR) {
                            stack_res.push_back(stack.back());
                        }
                        stack.pop_back();
                    } else {
                        break;
                    }
                }
                stack.push_back(token);
                break;
            }
            case TokenKind::L_BR: {
                stack.push_back(token);
                break;
            }
            case TokenKind::R_BR: {
                while (!stack.empty()
                       && stack.back().kind != TokenKind::L_BR) {
                    stack_res.push_back(stack.back());
                    stack.pop_back();
                }
                if (!stack.empty()) {
                    stack.pop_back();
                }
                break;
            }
            default: {
                stack_res.push_back(token);
            }
        }
    }

    while (!stack.empty()) {
        stack_res.push_back(stack.back());
        stack.pop_back();
    }
    for (auto& token : stack_res) {
        if (token.kind == TokenKind::NUMBER) {
            evalStack.push_back(new Ast(AstKind::NUMBER, token.value));

        } else if (token.kind == TokenKind::STR) {
            evalStack.push_back(new Ast(AstKind::STR, token.value));

        } else if (token.kind == TokenKind::VAR) {
            evalStack.push_back(new Ast(AstKind::VAR, token.value));

        } else if (token.kind == TokenKind::OP) {
            Ast* lhs = evalStack.back();
            evalStack.pop_back();

            Ast* rhs = evalStack.back();
            evalStack.pop_back();

            evalStack.push_back(
                new Ast(AstKind::OP, token.value, {rhs, lhs}));
        }
    }
    return evalStack[0];
}

Ast* Parser::stmt() {
    switch (currentToken().kind) {
        case TokenKind::IF: return if_stmt();
        case TokenKind::WHILE: return while_stmt();
        case TokenKind::NUMBER: return expr();
        case TokenKind::VAR:
            if (currentToken(+1).kind == TokenKind::ASSIGN_OP) {
                return assign_stmt();
            } else {
                return func_call();
            }
            break;
        case TokenKind::OP: return expr();
        case TokenKind::L_BR: return expr();
        default: throw "Error. This isn't a stmt";
    }
}

struct Value;

struct List {
    Value* data;
    List*  prev;
    List*  next;

    List() {
        data = nullptr;
        prev = nullptr;
        next = nullptr;
    }

    void insert(Value* newdata) {
        auto newNode  = new List();
        newNode->data = newdata;
        newNode->next = nullptr;

        auto ptr = this;
        while (ptr->next != nullptr) {
            ptr = ptr->next;
        }

        ptr->next     = newNode;
        newNode->prev = ptr;
    }

    Value* get(int newdata) {
        auto ptr   = this;
        int  index = 0;
        while (ptr != nullptr) {
            if (index == newdata) {
                return ptr->data;
            } else {
                ptr = ptr->next;
                ++index;
            }
        }
        throw "No element with matching index";
    }
};

bool operator==(const Value& a, const Value& b);

class Table
{
  public:
    struct Pair {
        Value* key;
        Value* value;
        Pair() = default;
    };

    struct Bucket {
        QVector<Pair> entries;
        Bucket() = default;
    };

    QVector<Bucket> bucket;

    Table() {
        elements_amount = 0;
        bucket          = QVector<Bucket>(4);
    };

    int elements_amount;

    int Hash(Value* key);

    void insert(Value* key, Value* value, bool recount = true);

    Value* get_table(Value* key);

    void resize();
};

enum class ValueKind
{
    Int,
    HashTable,
    LinkedList,
    String,
    Bool,
    Var
};

struct Value {
    private:
        ValueKind kind;
        int       intVal;
        QString   strVal;
        bool      boolVal;
        List*     listVal;
        Table*    tableVal;

    public:
        Value() = default;

        int hash() {
            return this->intVal;
        }

    friend bool operator==(const Value& a, const Value& b);

    int getIntVal() const {
        assert(kind == ValueKind::Int);
        return intVal;
    }

    QString getStrVal() const {
        assert(kind == ValueKind::String);
        return strVal;
    }

    QString getVarVal() const {
        assert(kind == ValueKind::Var);
        return strVal;
    }

    bool getBoolVal() const {
        assert(kind == ValueKind::Bool);
        return boolVal;
    }

    List* getListVal() const {
        assert(kind == ValueKind::LinkedList);
        return listVal;
    }

    Table* getTableVal() const {
        assert(kind == ValueKind::HashTable);
        return tableVal;
    }

    ValueKind getKind() const {
        return kind;
    }

    Value(int val) : kind(ValueKind::Int), intVal(val){};
    Value(QString val) : kind(ValueKind::String), strVal(val){};
    Value(ValueKind _kind, QString _string): kind(_kind), strVal(_string){};
    Value(bool val) : kind(ValueKind::Bool), boolVal(val){};
    Value(unsigned long val) : kind(ValueKind::Int), intVal(val){};
    Value(long long val) : kind(ValueKind::Int), intVal(val){};
    Value(List* _node) : kind(ValueKind::LinkedList), listVal(_node) {
        listVal->data = new Value(0);
    }

    Value(Table* _element)
        : kind(ValueKind::HashTable), tableVal(_element) {
    }

    Value* newCopy() {
        auto result = new Value();
        *result     = *this;
        return result;
    }
};

void Table::insert(Value* key, Value* value, bool recount) {
    auto idx = key->hash() % this->bucket.size();
    if (elements_amount * 2 > this->bucket.size()) {
        resize();
    }
    if (bucket[idx].entries.size() == 0) {
        bucket[idx].entries.push_back({key, value});
        if (recount) {
            elements_amount++;
        }
    } else {
        for (size_t pair_idx = 0;
             pair_idx < this->bucket[idx].entries.size();
             ++pair_idx) {
            if (*bucket[idx].entries[pair_idx].key == *key) {
                bucket[idx].entries[pair_idx].value = value;
                return;
            }
        }
        bucket[idx].entries.push_back({key, value});
        if (recount) {
            elements_amount++;
        }
    }
}

void Table::resize() {
    auto old_bucket = this->bucket;
    bucket          = QVector<Bucket>(this->bucket.size() * 2);
    std::cout << "Resize to " << bucket.size() << " buckets " << std::endl;
    for (auto& old : old_bucket) {
        for (auto& e : old.entries) {
            this->insert(e.key, e.value, false);
        }
    }
}

bool operator==(const Value& a, const Value& b) {
    bool result = a.kind == b.kind;
    if (result) {
        switch (a.kind) {
            case ValueKind::Int: return a.intVal == b.intVal;
            case ValueKind::String: return a.strVal == b.strVal;
        }
    }
    return result;
}

std::ostream& operator<<(std::ostream& os, const Value& value);

std::ostream& operator<<(std::ostream& os, List* value) {
    auto ptr = value;
    while (ptr != nullptr) {
        if (ptr->data == nullptr) {
            os << "NO DATA";
        } else {
            os << "->" << *ptr->data;
        }
        ptr = ptr->next;
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const Value& value) {
    os << "[";
    switch (value.getKind()) {
        case ValueKind::Int: {
            os << "Int " << value.getIntVal();
            break;
        }
        case ValueKind::Var: {
            os << "Var " << value.getVarVal().toStdString();
            break;
        }
        case ValueKind::String: {
            os << "String " << value.getStrVal().toStdString();
            break;
        }
        case ValueKind::Bool: {
            os << "Bool ";
            if (value.getBoolVal()) {
                os << "true";
            } else {
                os << "false";
            }
            break;
        }
        case ValueKind::LinkedList: {
            os << "List ";
            os << value.getListVal();
            break;
        }
        case ValueKind::HashTable: {
            os << "Table ";
            int cnt = 0;
            for (const auto& b : value.getTableVal()->bucket) {
                for (const auto& p : b.entries) {
                    if (cnt > 0) {
                        os << ", ";
                    }
                    os << "{" << *p.key << ": " << *p.value << "}";
                    ++cnt;
                }
            }
            break;
        }
    }
    os << "]";
    return os;
}

Value* Table::get_table(Value* key) {
    auto hash = key->hash();
    auto idx  = hash % this->bucket.size();
    for (size_t pair_idx = 0; pair_idx < this->bucket[idx].entries.size();
         ++pair_idx) {
        if (this->bucket[idx].entries.size() == 0) {
            std::cerr << "The bucket is empty" << std::endl;
            throw "Empty bucket";
        } else if (*this->bucket[idx].entries[pair_idx].key == *key) {
            return bucket[idx].entries[pair_idx].value;
        }
    }
    std::cerr << "No matching key " << *key << std::endl;
    abort();
}

struct Func {
    QString name;
    int     argCount;
    Func() = default;
    Func(QString _name, int _argc) : name(_name), argCount(_argc){};
};

enum class OPcode
{
    Load,
    Call,
    JumpIfFalse,
    Jump,
    Assign
};

struct Op {
    OPcode opcode;
    Value  arg;
    Func   func;
    Op() = default;
    Op(Value arg1) : opcode(OPcode::Load), arg(arg1){};
    Op(Func _func) : opcode(OPcode::Call), func(_func){};
    Op(OPcode _opcode) : opcode(_opcode){};
};

std::ostream& operator<<(std::ostream& os, OPcode op) {
    switch (op) {
        case OPcode::Load: return os << "Load";
        case OPcode::Call: return os << "Call";
        case OPcode::JumpIfFalse: return os << "JumpIfFalse";
        case OPcode::Jump: return os << "Jump";
        case OPcode::Assign: return os << "Assign";
    }
}

std::ostream& operator<<(std::ostream& os, Op op) {
    os << op.opcode << " ";
    switch (op.opcode) {
        case OPcode::Load: {
            os << op.arg;
            break;
        }
        case OPcode::Call: {
            os << "[ " << op.func.name.toStdString() << " ]"
               << "(" << op.func.argCount << ")";
            break;
        }
        case OPcode::Assign: {
            break;
        }
        default: break;
    }

    return os;
}

QVector<Op> compile(Ast* ast) {
    QVector<Op> result;
    switch (ast->kind) {
        case AstKind::NUMBER: {
            result.push_back(Op(Value(ast->str.toInt())));
            break;
        }
        case AstKind::VAR: {
            result.push_back(Op(Value(ValueKind::Var, ast->str)));
            break;
        }

        case AstKind::STR: {
            result.push_back(Op(Value(ValueKind::String, ast->str)));
            break;
        }

        case AstKind::func_call:
        case AstKind::OP: {
            for (Ast* node : ast->subnodes) {
                result.append(compile(node));
            }
            result.push_back(Op(Func(ast->str, ast->subnodes.size())));
            break;
        }

        case AstKind::assign_stmt: {
            for (Ast* node : ast->subnodes) {
                result.append(compile(node));
            }
            result.push_back(Op(OPcode::Assign));
            break;
        }

        case AstKind::value:
        case AstKind::expr:
        case AstKind::lang:
        case AstKind::stmt:
        case AstKind::else_body:
        case AstKind::stmt_list:
        case AstKind::while_body: {
            for (Ast* node : ast->subnodes) {
                result.append(compile(node));
            }
            break;
        }
        case AstKind::if_stmt: {
            auto body = compile(ast->subnodes[1]);
            result.append(compile(ast->subnodes[0]));
            bool hasElse = ast->subnodes.size() == 3;
            result.push_back(Op(Value(body.size() + (hasElse ? 3 : 1))));
            result.push_back(Op(OPcode::JumpIfFalse));
            result.append(body);

            if (hasElse) {
                auto else_body = compile(ast->subnodes[2]);
                result.push_back(Op(Value(else_body.size() + 1)));
                result.push_back(Op(OPcode::Jump));
                result.append(else_body);
            }
            break;
        }

        case AstKind::while_stmt: {
            auto condition = compile(ast->subnodes[0]);
            auto body      = compile(ast->subnodes[1]);
            result.append(condition);
            result.push_back(Op(Value(body.size() + 3)));
            result.push_back(Op(OPcode::JumpIfFalse));
            result.append(body);
            result.push_back(Op(Value(-(condition.size() + body.size() + 3))));
            result.push_back(Op(OPcode::Jump));
            break;
        }

        case AstKind::new_expr: {
            if (ast->str == "LinkedList") {
                result.push_back(Op(Value(new List())));
            } else if (ast->str == "HashTable") {
                result.push_back(Op(Value(new Table())));
            }
        }
    }
    return result;
}

std::optional<Value> evalFunc(QString name, QVector<Value> args) {
    if (name == "+") {
        return Value(args[0].getIntVal() + args[1].getIntVal());

    } else if (name == "*") {
        return Value(args[0].getIntVal() * args[1].getIntVal());

    } else if (name == "/") {
        return Value(args[0].getIntVal() / args[1].getIntVal());

    } else if (name == "==") {
        return Value(args[0].getIntVal() == args[1].getIntVal());

    } else if (name == "-") {
        return Value(args[0].getIntVal() - args[1].getIntVal());

    } else if (name == "print") {
        std::cout << "print: ";
        for (const auto& arg : args) {
            std::cout << arg << " ";
        }
        std::cout << std::endl;

    } else if (name == "<") {
        return Value(args[0].getIntVal() < args[1].getIntVal());

    } else if (name == ">") {
        return Value(args[0].getIntVal() > args[1].getIntVal());

    } else if (name == "add") {
        args[0].getListVal()->insert(args[1].newCopy());

    } else if (name == "get") {
        return *args[0].getListVal()->get(args[1].getIntVal());

    } else if (name == "set") {
        args[0].getTableVal()->insert(
            args[1].newCopy(), args[2].newCopy());

    } else if (name == "receive") {
        auto res = args[0].getTableVal()->get_table(args[1].newCopy());
        return *res;
    }

    return std::nullopt;
};

std::pair<QMap<QString, Value>, QVector<Value>> eval_code(
    QVector<Op> program,
    bool        printRun) {
    int                  programCounter = 0;
    QMap<QString, Value> var_table;
    QVector<Value>       stack;

    while (programCounter < program.size()) {
        auto cmd = program[programCounter];
        if (printRun) {
            std::cout << std::left << "@" << std::setw(4) << programCounter
                      << cmd << std::endl;
        }

        switch (cmd.opcode) {
            case OPcode::Load: {
                stack.push_back(cmd.arg);
                ++programCounter;
                break;
            }
            case OPcode::Call: {
                QVector<Value> args;
                for (int i = 0; i < cmd.func.argCount; ++i) {
                    auto value = stack.back();
                    if (value.getKind() == ValueKind::Var) {
                        value = var_table[value.getVarVal()];
                    }
                    args.push_back(value);
                    stack.pop_back();
                }

                std::reverse(args.begin(), args.end());

                auto res = evalFunc(cmd.func.name, args);
                if (res.has_value()) {
                    stack.push_back(res.value());
                }
                ++programCounter;
                break;
            }
            case OPcode::Assign: {
                auto value = stack.back();
                stack.pop_back();
                var_table[stack.back().getVarVal()] = value;
                stack.pop_back();
                ++programCounter;
                break;
            }
            case OPcode::JumpIfFalse: {
                auto jump_address = stack.back();
                stack.pop_back();
                auto condition = stack.back();
                stack.pop_back();
                if (condition.getBoolVal() == true) {
                    ++programCounter;
                } else {
                    programCounter = programCounter
                                     + jump_address.getIntVal();
                }
                break;
            }
            case OPcode::Jump: {
                auto jump_address = stack.back();
                stack.pop_back();
                programCounter = programCounter + jump_address.getIntVal();
                break;
            }
        }
    }
    return {var_table, stack};
}


struct TestConfig {
    QString code;
    bool    printAst;
    bool    printLex;
    bool    printPolish;
    bool    printEval;
    bool    printResult;
};

int main(int argc, char** argv) {
    std::vector<TestConfig> tests = {

    {"x = 10; a = (3 *(((((x / 2))))));", true, true, true, true, true},

    {"num = 5; while(num < 7) {num = num + 1;}", true, true, true, true, true},

    {"x = 15; y = 18; "
     "if (x == y) { print(1); } else { print(0); }", true, true, true, true, true},

    {"x = new LinkedList;\n"
        "\tadd(x, 69);\n"
        "\tadd(x, 13);\n"
        "\tadd(x, 5);\n"
        "\ty = get(x, 2);\n"
        "\tprint(y);",
         true, true, true, true, true},

    {"x = new HashTable; \n"
       "\tset(x, 5, 99); \n"
       "\tset(x, 0, 99); \n"
       "\tset(x, 9, 33); \n"
       "\tset(x, 8, 19); \n"
       "\ty = receive(x, 9);",
        true, true, true, true, true},
};

    for (
        const auto& [code, printAst, printLex, printPolish, printEval, printResult] :
        tests) {
        std::cout << "\033[32m\033[1mEXAMPLE\033[0m [" << code.toStdString()
                  << "]\n";
        std::cout << "---------------------------------------------\n";

        auto parser = new Parser(lexer(code, printLex));
        auto ast    = parser->parse();

        if (printAst) {
            std::cout << "\033[33m\033[1m\nAbstract syntax tree (AST):\033[0m"<< std::endl;
            ast->print(0);
        }

        std::cout << std::endl;
        QVector<Op> program = compile(ast);

        if (printPolish) {
            std::cout << "\033[31m\033[1mReverse Polish notation and Stack-machine:\033[0m"<< std::endl;
            for (int i = 0; i < program.size(); ++i) {
                std::cout << std::left << std::setw(6) << i << " "
                          << program[i] << std::endl;
            }
        }


        auto result = eval_code(program, printEval);

        if (printResult) {
            std::cout << "--- variable table ---\n";
            for (const auto& key : result.first.keys()) {
                std::cout << key.toStdString() << " = "
                          << result.first[key] << "\n";
            }

            std::cout << "--- stack values---\n\n";
            for (const auto& val : result.second) {
                std::cout << val << "\n";
            }
        }
    }
}
