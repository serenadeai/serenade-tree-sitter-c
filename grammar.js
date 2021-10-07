const PREC = {
  PAREN_DECLARATOR: -10,
  ASSIGNMENT: -1,
  CONDITIONAL: -2,
  DEFAULT: 0,
  LOGICAL_OR: 1,
  LOGICAL_AND: 2,
  INCLUSIVE_OR: 3,
  EXCLUSIVE_OR: 4,
  BITWISE_AND: 5,
  EQUAL: 6,
  RELATIONAL: 7,
  SIZEOF: 8,
  SHIFT: 9,
  ADD: 10,
  MULTIPLY: 11,
  CAST: 12,
  UNARY: 13,
  CALL: 14,
  FIELD: 15,
  SUBSCRIPT: 16
};

module.exports = grammar({
  name: 'c',

  extras: $ => [
    /\s|\\\r?\n/,
    $.comment,
  ],

  inline: $ => [
    // $.statement,
    // $.top_level_item,
    $._type_identifier,
    $._field_identifier,
    $._statement_identifier,
    $._non_case_statement,
    $._assignment_left_expression,
  ],

  conflicts: $ => [
    [$._type_specifier, $._declarator],
    [$._type_specifier, $._declarator, $.macro_type_specifier],
    [$._type_specifier, $._expression],
    [$._type_specifier, $._expression, $.macro_type_specifier],
    [$._type_specifier, $.macro_type_specifier],
    [$.sized_type_specifier],

    [$.program, $.top_level_item],
    [$.if],
    [$.if_clause, $.else_if_clause],
  ],

  word: $ => $.identifier,

  rules: {
    program: $ => seq(
      optional_with_placeholder('import_list', repeat(prec.dynamic(1, $.preproc_include))),
      optional_with_placeholder('statement_list', repeat($.top_level_item))
    ),

    top_level_item: $ => choice(
      $.function_definition,
      $.linkage_specification,
      $.declaration,
      $.statement,
      $.type_definition,
      $.empty_declaration,
      $.preproc_if,
      $.preproc_ifdef,
      $.preproc_include,
      $.preproc_def,
      $.preproc_function_def,
      $.preproc_call
    ),

    // Preprocesser

    preproc_include: $ => seq(
      preprocessor('include'),
      field('path', choice(
        $.string_literal,
        $.system_lib_string,
        $.identifier,
        alias($.preproc_call_expression, $.call_expression),
      )),
      '\n'
    ),

    preproc_def: $ => seq(
      preprocessor('define'),
      field('name', $.identifier),
      field('value', optional($.preproc_arg)),
      '\n'
    ),

    preproc_function_def: $ => seq(
      preprocessor('define'),
      field('name', $.identifier),
      field('parameters', $.preproc_params),
      field('value', optional($.preproc_arg)),
      '\n'
    ),

    preproc_params: $ => seq(
      token.immediate('('), commaSep(choice($.identifier, '...')), ')'
    ),

    preproc_call: $ => seq(
      field('directive', $.preproc_directive),
      field('argument', optional($.preproc_arg)),
      '\n'
    ),

    ...preprocIf('', $ => $.top_level_item),
    ...preprocIf('_in_field_declaration_list', $ => $._field_declaration_list_item),

    preproc_directive: $ => /#[ \t]*[a-zA-Z]\w*/,
    preproc_arg: $ => token(prec(-1, repeat1(/.|\\\r?\n/))),

    _preproc_expression: $ => choice(
      $.identifier,
      alias($.preproc_call_expression, $.call_expression),
      $.number_literal,
      $.char_literal,
      $.preproc_defined,
      alias($.preproc_unary_expression, $.unary_expression),
      alias($.preproc_binary_expression, $.binary_expression),
      alias($.preproc_parenthesized_expression, $.parenthesized_expression)
    ),

    preproc_parenthesized_expression: $ => seq(
      '(',
      $._preproc_expression,
      ')'
    ),

    preproc_defined: $ => choice(
      prec(PREC.CALL, seq('defined', '(', $.identifier, ')')),
      seq('defined', $.identifier),
    ),

    preproc_unary_expression: $ => prec.left(PREC.UNARY, seq(
      field('operator', choice('!', '~', '-', '+')),
      field('argument', $._preproc_expression)
    )),

    preproc_call_expression: $ => prec(PREC.CALL, seq(
      field('function_', $.identifier),
      field('arguments', alias($.preproc_argument_list, $.argument_list_block))
    )),

    preproc_argument_list: $ => seq(
      '(',
      commaSep($._preproc_expression),
      ')'
    ),

    preproc_binary_expression: $ => {
      const table = [
        ['+', PREC.ADD],
        ['-', PREC.ADD],
        ['*', PREC.MULTIPLY],
        ['/', PREC.MULTIPLY],
        ['%', PREC.MULTIPLY],
        ['||', PREC.LOGICAL_OR],
        ['&&', PREC.LOGICAL_AND],
        ['|', PREC.INCLUSIVE_OR],
        ['^', PREC.EXCLUSIVE_OR],
        ['&', PREC.BITWISE_AND],
        ['==', PREC.EQUAL],
        ['!=', PREC.EQUAL],
        ['>', PREC.RELATIONAL],
        ['>=', PREC.RELATIONAL],
        ['<=', PREC.RELATIONAL],
        ['<', PREC.RELATIONAL],
        ['<<', PREC.SHIFT],
        ['>>', PREC.SHIFT],
      ];

      return choice(...table.map(([operator, precedence]) => {
        return prec.left(precedence, seq(
          field('left', $._preproc_expression),
          field('operator', operator),
          field('right', $._preproc_expression)
        ))
      }));
    },

    // Main Grammar

    function_definition: $ => seq(
      optional($.ms_call_modifier),
      $.declaration_specifiers,
      field('declarator', $._declarator),
      field('body', $.enclosed_body)
    ),

    declaration_without_semicolon: $ => seq(
      $.declaration_specifiers,
      commaSep1(field('top_level_declarator', choice(
        $._declarator,
        $.init_declarator
      )))
    ), 

    declaration: $ => seq(
      $.declaration_without_semicolon,
      ';'
    ),

    type_definition: $ => seq(
      'typedef',
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('type', $._type_specifier),
      commaSep1(field('declarator', $._type_declarator)),
      ';'
    ),

    declaration_specifier: $ => choice(
      $.storage_class_specifier,
      $.type_qualifier,
      $.attribute_specifier,
      $.ms_declspec_modifier
    ),

    declaration_specifiers: $ => seq(
      optional_with_placeholder('modifier_list', repeat($.declaration_specifier)),
      field('type', $._type_specifier),
      optional_with_placeholder('modifier_list', repeat($.declaration_specifier)),
    ),

    linkage_specification: $ => seq(
      'extern',
      field('value', $.string_literal),
      field('body', choice(
        $.function_definition,
        $.declaration,
        $.declaration_list
      ))
    ),

    attribute_specifier: $ => field('modifier', seq(
      '__attribute__',
      '(',
      $.argument_list_block,
      ')'
    )),

    ms_declspec_modifier: $ => field('modifier', seq(
      '__declspec',
      '(',
      $.identifier,
      ')',
    )),

    ms_based_modifier: $ => seq(
      '__based',
      $.argument_list_block,
    ),

    ms_call_modifier: $ => choice(
      '__cdecl',
      '__clrcall',
      '__stdcall',
      '__fastcall',
      '__thiscall',
      '__vectorcall'
    ),

    ms_restrict_modifier: $ => '__restrict',

    ms_unsigned_ptr_modifier: $ => '__uptr',

    ms_signed_ptr_modifier: $ => '__sptr',

    ms_unaligned_ptr_modifier: $ => choice('_unaligned', '__unaligned'),

    ms_pointer_modifier: $ => choice(
      $.ms_unaligned_ptr_modifier,
      $.ms_restrict_modifier,
      $.ms_unsigned_ptr_modifier,
      $.ms_signed_ptr_modifier,
    ),

    declaration_list: $ => seq(
      '{',
      optional_with_placeholder('statement_list', repeat($.top_level_item)),
      '}'
    ),

    _declarator: $ => choice(
      $.pointer_declarator,
      $.function_declarator,
      $.array_declarator,
      $.parenthesized_declarator,
      $.identifier
    ),

    _field_declarator: $ => choice(
      alias($.pointer_field_declarator, $.pointer_declarator),
      alias($.function_field_declarator, $.function_declarator),
      alias($.array_field_declarator, $.array_declarator),
      alias($.parenthesized_field_declarator, $.parenthesized_declarator),
      $._field_identifier
    ),

    _type_declarator: $ => choice(
      alias($.pointer_type_declarator, $.pointer_declarator),
      alias($.function_type_declarator, $.function_declarator),
      alias($.array_type_declarator, $.array_declarator),
      alias($.parenthesized_type_declarator, $.parenthesized_declarator),
      $._type_identifier
    ),

    _abstract_declarator: $ => choice(
      $.abstract_pointer_declarator,
      $.abstract_function_declarator,
      $.abstract_array_declarator,
      $.abstract_parenthesized_declarator,
    ),

    parenthesized_declarator: $ => prec.dynamic(PREC.PAREN_DECLARATOR, seq(
      '(',
      $._declarator,
      ')'
    )),
    parenthesized_field_declarator: $ => prec.dynamic(PREC.PAREN_DECLARATOR, seq(
      '(',
      $._field_declarator,
      ')'
    )),
    parenthesized_type_declarator: $ => prec.dynamic(PREC.PAREN_DECLARATOR, seq(
      '(',
      $._type_declarator,
      ')'
    )),
    abstract_parenthesized_declarator: $ => prec(1, seq(
      '(',
      $._abstract_declarator,
      ')'
    )),



    pointer_declarator: $ => prec.dynamic(1, prec.right(seq(
      optional($.ms_based_modifier),
      '*',
      repeat($.ms_pointer_modifier),
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('declarator', $._declarator)
    ))),
    pointer_field_declarator: $ => prec.dynamic(1, prec.right(seq(
      optional($.ms_based_modifier),
      '*',
      repeat($.ms_pointer_modifier),
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('declarator', $._field_declarator)
    ))),
    pointer_type_declarator: $ => prec.dynamic(1, prec.right(seq(
      optional($.ms_based_modifier),
      '*',
      repeat($.ms_pointer_modifier),
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('declarator', $._type_declarator)
    ))),
    abstract_pointer_declarator: $ => prec.dynamic(1, prec.right(seq('*',
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('declarator', optional($._abstract_declarator))
    ))),

    function_declarator: $ => prec(1,
      seq(
        field('declarator', $._declarator),
        field('parameters', $.parameter_list_block),
        repeat($.attribute_specifier),
      )),
    function_field_declarator: $ => prec(1, seq(
      field('declarator', $._field_declarator),
      field('parameters', $.parameter_list_block)
    )),
    function_type_declarator: $ => prec(1, seq(
      field('declarator', $._type_declarator),
      field('parameters', $.parameter_list_block)
    )),
    abstract_function_declarator: $ => prec(1, seq(
      field('declarator', optional($._abstract_declarator)),
      field('parameters', $.parameter_list_block)
    )),

    array_declarator: $ => prec(1, seq(
      field('declarator', $._declarator),
      '[',
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('size', optional(choice($._expression, '*'))),
      ']'
    )),
    array_field_declarator: $ => prec(1, seq(
      field('declarator', $._field_declarator),
      '[',
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('size', optional(choice($._expression, '*'))),
      ']'
    )),
    array_type_declarator: $ => prec(1, seq(
      field('declarator', $._type_declarator),
      '[',
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('size', optional(choice($._expression, '*'))),
      ']'
    )),
    abstract_array_declarator: $ => prec(1, seq(
      field('declarator', optional($._abstract_declarator)),
      '[',
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('size', optional(choice($._expression, '*'))),
      ']'
    )),

    init_declarator: $ => seq(
      field('declarator', $._declarator),
      '=',
      field('value', choice($.initializer_list, $._expression))
    ),

    enclosed_body: $ => seq(
      '{',
      optional_with_placeholder('statement_list', repeat($.top_level_item)),
      '}'
    ),

    storage_class_specifier: $ => field('modifier', choice(
      'extern',
      'static' ,
      'auto',
      'register',
      'inline'
    )),

    type_qualifier: $ => field('modifier', choice(
      'const',
      'volatile',
      'restrict',
      '_Atomic'
    )),

    _type_specifier: $ => choice(
      $.struct_specifier,
      $.union_specifier,
      $.enum_specifier,
      $.macro_type_specifier,
      $.sized_type_specifier,
      $.primitive_type,
      $._type_identifier
    ),

    sized_type_specifier: $ => seq(
      repeat1(choice(
        'signed',
        'unsigned',
        'long',
        'short'
      )),
      field('type', optional(choice(
        prec.dynamic(-1, $._type_identifier),
        $.primitive_type
      )))
    ),

    primitive_type: $ => token(choice(
      'bool',
      'char',
      'int',
      'float',
      'double',
      'void',
      'size_t',
      'ssize_t',
      'intptr_t',
      'uintptr_t',
      'charptr_t',
      ...[8, 16, 32, 64].map(n => `int${n}_t`),
      ...[8, 16, 32, 64].map(n => `uint${n}_t`),
      ...[8, 16, 32, 64].map(n => `char${n}_t`)
    )),

    enum_specifier: $ => seq(
      'enum',
      choice(
        seq(
          field('name', $._type_identifier),
          field('body', optional($.enumerator_list_block))
        ),
        field('body', $.enumerator_list_block)
      )
    ),

    enumerator_list_block: $ => seq(
      '{',
      optional_with_placeholder(
        'enum_member_list',
        seq(
          commaSep($.enumerator),
          optional(',')
      )),
      '}'
    ),

    struct_specifier: $ => seq(
      'struct',
      optional($.ms_declspec_modifier),
      choice(
        seq(
          field('name', $._type_identifier),
          field('body', optional($.field_declaration_list))
        ),
        field('body', $.field_declaration_list)
      )
    ),

    union_specifier: $ => seq(
      'union',
      optional($.ms_declspec_modifier),
      choice(
        seq(
          field('name', $._type_identifier),
          field('body', optional($.field_declaration_list))
        ),
        field('body', $.field_declaration_list)
      )
    ),

    field_declaration_list: $ => seq(
      '{',
      optional_with_placeholder('class_member_list',
        repeat($._field_declaration_list_item)
      ),
      '}'
    ),

    _field_declaration_list_item: $ => choice(
      $.field_declaration,
      $.preproc_def,
      $.preproc_function_def,
      $.preproc_call,
      alias($.preproc_if_in_field_declaration_list, $.preproc_if),
      alias($.preproc_ifdef_in_field_declaration_list, $.preproc_ifdef),
    ),

    field_declaration: $ => seq(
      $.declaration_specifiers,
      commaSep(field('declarator', $._field_declarator)),
      optional($.bitfield_clause),
      ';'
    ),

    bitfield_clause: $ => seq(':', $._expression),

    enumerator: $ => seq(
      field('name', $.identifier),
      optional(seq('=', field('value', $._expression)))
    ),

    parameter_list: $ => commaSep1(field('parameter', choice($.parameter_declaration, '...'))),

    parameter_list_block: $ => seq(
      '(',
      optional_with_placeholder('parameter_list', $.parameter_list),
      ')'
    ),

    parameter_declaration: $ => seq(
      $.declaration_specifiers,
      optional(field('declarator', choice(
        $._declarator,
        $._abstract_declarator
      )))
    ),

    // Statements

    statement: $ => choice(
      $.case_statement,
      $._non_case_statement
    ),

    _non_case_statement: $ => choice(
      $.labeled_statement,
      $.enclosed_body,
      $.expression_statement,
      $.if,
      $.switch_statement,
      $.do_statement,
      $.while_statement,
      $.for,
      $.return_statement,
      $.break_statement,
      $.continue_statement,
      $.goto_statement
    ),

    labeled_statement: $ => seq(
      field('label', $._statement_identifier),
      ':',
      $.statement
    ),

    expression_statement: $ => seq(
      optional(choice(
        $._expression,
        $.comma_expression
      )),
      ';'
    ),

    condition: $ => choice($._expression, $.comma_expression),

    if: $ => seq(
      $.if_clause, 
      optional_with_placeholder(
        'else_if_clause_list',
        repeat($.else_if_clause)
      ),
      optional_with_placeholder('else_clause_optional', $.else_clause)
    ),

    if_clause: $ => prec.dynamic(0, 
      seq('if', '(', $.condition, ')', $.statement),
    ),

    else_if_clause: $ => prec.dynamic(1, seq(
      'else', 'if', '(', $.condition, ')', $.statement
    )), 

    else_clause: $ => seq('else', $.statement),

    switch_statement: $ => seq(
      'switch',
      '(', 
      $.condition, 
      ')', 
      field('body', $.enclosed_body)
    ),

    case_statement: $ => prec.right(seq(
      choice(
        seq('case', field('value', $._expression)),
        'default'
      ),
      ':',
      repeat(choice(
        $._non_case_statement,
        $.declaration,
        $.type_definition
      ))
    )),

    while_statement: $ => seq(
      'while',
      '(', 
      $.condition, 
      ')', 
      field('body', $.statement)
    ),

    do_statement: $ => seq(
      'do',
      field('body', $.statement),
      'while',
      field('condition', $.parenthesized_expression),
      ';'
    ),

    for: $ => $.for_clause,

    for_clause: $ => seq(
      'for',
      '(',
      optional_with_placeholder('block_initializer_optional', $.block_initializer),
      // choice(
      //   field('initializer', $.declaration),
      //   seq(field('initializer', optional(choice($._expression, $.comma_expression))), ';')
      // ),
      ';', 
      optional_with_placeholder('condition_optional', alias($._expression, $.condition)),
      ';',
      optional_with_placeholder('block_update_optional', $.block_update),
      // field('condition', optional($._expression)), ';',
      // field('update', optional(choice($._expression, $.comma_expression))),
      ')',
      $.statement
    ),

    block_initializer: $ => choice(
      $.declaration_without_semicolon,
      choice($._expression, $.comma_expression)
    ), 

    block_update: $ => choice($._expression, $.comma_expression), 

    return_value: $ => choice($._expression, $.comma_expression), 

    return_statement: $ => seq(
      'return',
      optional_with_placeholder('return_value_optional', $.return_value),
      ';'
    ),

    break_statement: $ => seq(
      'break', ';'
    ),

    continue_statement: $ => seq(
      'continue', ';'
    ),

    goto_statement: $ => seq(
      'goto',
      field('label', $._statement_identifier),
      ';'
    ),

    // Expressions

    _expression: $ => choice(
      $.conditional_expression,
      $.assignment_expression,
      $.binary_expression,
      $.unary_expression,
      $.update_expression,
      $.cast_expression,
      $.pointer_expression,
      $.sizeof_expression,
      $.subscript_expression,
      $.call_expression,
      $.field_expression,
      $.compound_literal_expression,
      $.identifier,
      $.number_literal,
      $.string_literal,
      $.true,
      $.false,
      $.null,
      $.concatenated_string,
      $.char_literal,
      $.parenthesized_expression
    ),

    comma_expression: $ => seq(
      field('left', $._expression),
      ',',
      field('right', choice($._expression, $.comma_expression))
    ),

    conditional_expression: $ => prec.right(PREC.CONDITIONAL, seq(
      field('condition', $._expression),
      '?',
      field('consequence', $._expression),
      ':',
      field('alternative', $._expression)
    )),

    _assignment_left_expression: $ => choice(
      $.identifier,
      $.call_expression,
      $.field_expression,
      $.pointer_expression,
      $.subscript_expression,
      $.parenthesized_expression
    ),

    assignment_expression: $ => prec.right(PREC.ASSIGNMENT, seq(
      field('left', $._assignment_left_expression),
      field('operator', choice(
        '=',
        '*=',
        '/=',
        '%=',
        '+=',
        '-=',
        '<<=',
        '>>=',
        '&=',
        '^=',
        '|='
      )),
      field('right', $._expression)
    )),

    pointer_expression: $ => prec.left(PREC.CAST, seq(
      field('operator', choice('*', '&')),
      field('argument', $._expression)
    )),

    unary_expression: $ => prec.left(PREC.UNARY, seq(
      field('operator', choice('!', '~', '-', '+')),
      field('argument', $._expression)
    )),

    binary_expression: $ => {
      const table = [
        ['+', PREC.ADD],
        ['-', PREC.ADD],
        ['*', PREC.MULTIPLY],
        ['/', PREC.MULTIPLY],
        ['%', PREC.MULTIPLY],
        ['||', PREC.LOGICAL_OR],
        ['&&', PREC.LOGICAL_AND],
        ['|', PREC.INCLUSIVE_OR],
        ['^', PREC.EXCLUSIVE_OR],
        ['&', PREC.BITWISE_AND],
        ['==', PREC.EQUAL],
        ['!=', PREC.EQUAL],
        ['>', PREC.RELATIONAL],
        ['>=', PREC.RELATIONAL],
        ['<=', PREC.RELATIONAL],
        ['<', PREC.RELATIONAL],
        ['<<', PREC.SHIFT],
        ['>>', PREC.SHIFT],
      ];

      return choice(...table.map(([operator, precedence]) => {
        return prec.left(precedence, seq(
          field('left', $._expression),
          field('operator', operator),
          field('right', $._expression)
        ))
      }));
    },

    update_expression: $ => {
      const argument = field('argument', $._expression);
      const operator = field('operator', choice('--', '++'));
      return prec.right(PREC.UNARY, choice(
        seq(operator, argument),
        seq(argument, operator),
      ));
    },

    cast_expression: $ => prec(PREC.CAST, seq(
      '(',
      field('type', $.type_descriptor),
      ')',
      field('value', $._expression)
    )),

    type_descriptor: $ => seq(
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('type', $._type_specifier),
      optional_with_placeholder('modifier_list', repeat($.type_qualifier)),
      field('declarator', optional($._abstract_declarator))
    ),

    sizeof_expression: $ => prec(PREC.SIZEOF, seq(
      'sizeof',
      choice(
        field('value', $._expression),
        seq('(', field('type', $.type_descriptor), ')')
      )
    )),

    subscript_expression: $ => prec(PREC.SUBSCRIPT, seq(
      field('argument', $._expression),
      '[',
      field('index', $._expression),
      ']'
    )),

    call_expression: $ => prec(PREC.CALL, seq(
      field('function', $._expression),
      field('arguments', $.argument_list_block)
    )),

    argument: $ => $._expression, 

    argument_list: $ => commaSep1($.argument), 

    argument_list_block: $ => seq('(', optional_with_placeholder('argument_list', $.argument_list), ')'),

    field_expression: $ => seq(
      prec(PREC.FIELD, seq(
        field('argument', $._expression),
        field('operator', choice('.', '->'))
      )),
      field('field', $._field_identifier)
    ),

    compound_literal_expression: $ => seq(
      '(',
      field('type', $.type_descriptor),
      ')',
      field('value', $.initializer_list)
    ),

    parenthesized_expression: $ => seq(
      '(',
      choice($._expression, $.comma_expression),
      ')'
    ),

    initializer_list: $ => seq(
      '{',
      commaSep(choice(
        $.initializer_pair,
        $._expression,
        $.initializer_list
      )),
      optional(','),
      '}'
    ),

    initializer_pair: $ => seq(
      field('designator', repeat1(choice($.subscript_designator, $.field_designator))),
      '=',
      field('value', choice($._expression, $.initializer_list))
    ),

    subscript_designator: $ => seq('[', $._expression, ']'),

    field_designator: $ => seq('.', $._field_identifier),

    number_literal: $ => {
      const separator = "'";
      const hex = /[0-9a-fA-F]/;
      const decimal = /[0-9]/;
      const hexDigits = seq(repeat1(hex), repeat(seq(separator, repeat1(hex))));
      const decimalDigits = seq(repeat1(decimal), repeat(seq(separator, repeat1(decimal))));
      return token(seq(
        optional(/[-\+]/),
        optional(choice('0x', '0b')),
        choice(
          seq(
            choice(
              decimalDigits,
              seq('0b', decimalDigits),
              seq('0x', hexDigits)
            ),
            optional(seq('.', optional(hexDigits)))
          ),
          seq('.', decimalDigits)
        ),
        optional(seq(
          /[eEpP]/,
          optional(seq(
            optional(/[-\+]/),
            hexDigits
          ))
        )),
        repeat(choice('u', 'l', 'U', 'L', 'f', 'F'))
      ))
    },

    char_literal: $ => seq(
      choice('L\'', 'u\'', 'U\'', 'u8\'', '\''),
      choice(
        $.escape_sequence,
        token.immediate(/[^\n']/)
      ),
      '\''
    ),

    concatenated_string: $ => seq(
      $.string_literal,
      repeat1($.string_literal)
    ),

    string_literal: $ => seq(
      choice('L"', 'u"', 'U"', 'u8"', '"'),
      repeat(choice(
        token.immediate(prec(1, /[^\\"\n]+/)),
        $.escape_sequence
      )),
      '"',
    ),

    escape_sequence: $ => token(prec(1, seq(
      '\\',
      choice(
        /[^xuU]/,
        /\d{2,3}/,
        /x[0-9a-fA-F]{2,}/,
        /u[0-9a-fA-F]{4}/,
        /U[0-9a-fA-F]{8}/
      )
    ))),

    system_lib_string: $ => token(seq(
      '<',
      repeat(choice(/[^>\n]/, '\\>')),
      '>'
    )),

    true: $ => token(choice('TRUE', 'true')),
    false: $ => token(choice('FALSE', 'false')),
    null: $ => 'NULL',

    identifier: $ => /[a-zA-Z_]\w*/,

    _type_identifier: $ => $.identifier,
    _field_identifier: $ => $.identifier,
    _statement_identifier: $ => $.identifier,

    empty_declaration: $ => seq(
      $._type_specifier,
      ';'
    ),

    macro_type_specifier: $ => prec.dynamic(-1, seq(
      field('name', $.identifier),
      '(',
      field('type', $.type_descriptor),
      ')'
    )),

    // http://stackoverflow.com/questions/13014947/regex-to-match-a-c-style-multiline-comment/36328890#36328890
    comment: $ => token(choice(
      seq('//', /(\\(.|\r?\n)|[^\\\n])*/),
      seq(
        '/*',
        /[^*]*\*+([^/*][^*]*\*+)*/,
        '/'
      )
    )),
  },

  supertypes: $ => [
    $._expression,
    $.statement,
    $._type_specifier,
    $._declarator,
    $._field_declarator,
    $._type_declarator,
    $._abstract_declarator,
  ]
});

module.exports.PREC = PREC

function preprocIf (suffix, content) {
  function elseBlock ($) {
    return choice(
      suffix ? alias($['preproc_else' + suffix], $.preproc_else) : $.preproc_else,
      suffix ? alias($['preproc_elif' + suffix], $.preproc_elif) : $.preproc_elif,
    );
  }

  return {
    ['preproc_if' + suffix]: $ => seq(
      preprocessor('if'),
      field('condition', $._preproc_expression),
      '\n',
      repeat(content($)),
      field('alternative', optional(elseBlock($))),
      preprocessor('endif')
    ),

    ['preproc_ifdef' + suffix]: $ => seq(
      choice(preprocessor('ifdef'), preprocessor('ifndef')),
      field('name', $.identifier),
      repeat(content($)),
      field('alternative', optional(elseBlock($))),
      preprocessor('endif')
    ),

    ['preproc_else' + suffix]: $ => seq(
      preprocessor('else'),
      repeat(content($))
    ),

    ['preproc_elif' + suffix]: $ => seq(
      preprocessor('elif'),
      field('condition', $._preproc_expression),
      '\n',
      repeat(content($)),
      field('alternative', optional(elseBlock($))),
    )
  }
}

function preprocessor (command) {
  return alias(new RegExp('#[ \t]*' + command), '#' + command)
}

function commaSep (rule) {
  return optional(commaSep1(rule))
}

function commaSep1 (rule) {
  return seq(rule, repeat(seq(',', rule)))
}

function commaSepTrailing (recurSymbol, rule) {
  return choice(rule, seq(recurSymbol, ',', rule))
}

function optional_with_placeholder(field_name, rule) {
  return choice(field(field_name, rule), field(field_name, blank()));
}
