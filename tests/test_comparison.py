import pytest
from cobol_javatrans.scoring import cobol_matches, extract_code


@pytest.mark.parametrize('output,type_,expected,match', [
    ('1\n','Bool','True',True), ('true\n','Bool','False',True),
    ('0\n','Bool','True',False), (' y23\n','Int','-23',True),
    ('p23\n','Int','-23',True), ('-23\n','Int','-23',True),
    ('bad\n','Int','0',False), ('1.0009\n','Float','1.0',True),
    ('1.0011\n','Float','1.0',False), ('p1.5\n','Float','-1.5',True),
    ('y1.5\n','Float','-1.5',True), ('  hi \n','String',"'hi'",True),
    ('1\n2\n999\n',{'List':'Int'},'[1,2]',True),
    ('1\n2\nbad\n',{'List':'Int'},'[1,2]',False),
    ('1\n',{'List':'Int'},'[1,2]',False),
    ('1\n2\n',{'List':'Int'},'(1,2)',True),
    ('a\n b\n',{'List':'String'},"['a','b']",True),
    ('1.0001\n',{'List':'Float'},'[1.0,2.0]',True),  # upstream zip, no length guard
    ('1.01\n',{'List':'Float'},'[1.0]',False),
    ('','Bool','False',False), ('\n','String',"''",True),
    ('1\n','Unsupported','1',False),
])
def test_faithful_upstream_edge_cases(output, type_, expected, match):
    assert cobol_matches(output, dict(type_=type_, value=expected)) is match


def test_java_upstream_duplicate_import_cleaning():
    code = 'a' * 100 + 'suffix import java.util.*;'
    assert extract_code('```java\n'+code+'\n```', 'java') == 'a'*100+'suffix '


def test_cobol_upstream_section_reordering():
    code = '       IDENTIFICATION DIVISION.\n       LINKAGE SECTION.\n       01 LINKED-ITEMS.\n       WORKING-STORAGE SECTION.\n       PROCEDURE DIVISION USING LINKED-ITEMS.\n'
    cleaned = extract_code('```cobol\n'+code+'```', 'cobol')
    assert cleaned.index('WORKING-STORAGE') < cleaned.index('LINKAGE') < cleaned.index('PROCEDURE')


def test_readlines_preserves_vertical_tabs_inside_strings():
    assert cobol_matches('a\vb\n', {'type_': 'String', 'value': repr('a\vb')})
