"""Exercise C++ AST forms that differ from LAVA's original C function analysis."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml


@pytest.fixture
def query_runtime_include(tmp_path):
    """Test source rewrites without requiring PANDA guest headers in quick CI."""
    header = tmp_path / 'include/lava/pirate_mark_lava.h'
    header.parent.mkdir(parents=True)
    header.write_text(
        'static inline void vm_lava_pri_query_point(unsigned int id, unsigned long line, unsigned long extra) {}\n'
        'static inline void vm_lava_attack_point(unsigned int id, unsigned long line, unsigned int info) {}\n')
    return '-I' + str(header.parent.parent)


def test_function_analysis_handles_cpp_initializers_and_dependent_calls(tmp_path):
    tool = os.environ.get('LAVA_FN_TOOL') or shutil.which('lavaFnTool')
    compiler = shutil.which('clang++-14')
    if not tool or not compiler:
        pytest.skip('lavaFnTool and clang++-14 required')
    source = tmp_path / 'initializers.cpp'
    source.write_text('''
int target(int value) { return value; }
template<class T> auto dependent(T value) -> decltype(value.call()) {
    return value.call();
}
int main() {
    int *empty{};
    int (*callback)(int) = target;
    return empty != nullptr || callback(0);
}
''')
    (tmp_path / 'compile_commands.json').write_text(json.dumps([{
        'directory': str(tmp_path), 'file': str(source),
        'arguments': [compiler, '-std=c++14', '-c', str(source)],
    }]))
    subprocess.run([tool, str(source)], cwd=tmp_path, check=True,
                   capture_output=True, text=True, timeout=30)
    records = yaml.safe_load(Path(str(source) + '.fn').read_text())
    assert any(record.get('fun', {}).get('name') == 'main' for record in records)
    assert any(record.get('fnPtrAssign', {}).get('name') == 'target' for record in records)
    assert any(record.get('call', {}).get('containing_function') == 'dependent'
               for record in records)


def test_cpp_queries_preserve_constant_evaluation_and_template_instantiations(tmp_path, query_runtime_include):
    tool = os.environ.get('LAVA_QUERY_TOOL') or shutil.which('lavaTool')
    compiler = shutil.which('clang++-14')
    apply = shutil.which('clang-apply-replacements-14')
    if not tool or not compiler or not apply:
        pytest.skip('lavaTool and Clang 14 tools required')
    source = tmp_path / 'queries.cpp'
    source.write_text('''
#include <initializer_list>
constexpr int constant(int value) { return value + 1; }
static_assert(constant(1) == 2, "constant evaluation must survive");
template<class T> T identity(T value) { return value; }
struct Handler {
    Handler() = default;
    virtual ~Handler() = default;
    int call(int value) { return value + 1; }
};
struct Throwing {
    Throwing() try {} catch (...) { throw; }
};
int callback(int value) { return value; }
int invoke(int (*function)(int), int value) { return function(value); }
void read(int &value) { value = 3; }
int pointer(const int *value) { return value ? 1 : 0; }
int overload(short) { return 0; }
int overload(int) { return 1; }
int main() {
    Handler handler;
    Throwing throwing;
    int value = 0;
    read(value);
    short narrow = 1;
    std::initializer_list<int> range = {1, 2};
    int sum = 0;
    for (const auto &element : range) { sum += element; }
    return handler.call(identity(0)) != 1 || identity(0L) != 0
        || invoke(&callback, 0) != 0 || value != 3 || pointer(0) != 0
        || overload(narrow) != 0 || sum != 3;
}
''')
    (tmp_path / 'compile_commands.json').write_text(json.dumps([{
        'directory': str(tmp_path), 'file': str(source),
        'arguments': [compiler, '-std=c++14', '-c', str(source)],
    }]))
    subprocess.run([tool, '-action=query', '-p=' + str(tmp_path),
                    '-src-prefix=' + str(tmp_path), str(source)],
                   cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30)
    subprocess.run([apply, str(tmp_path)], cwd=tmp_path, check=True,
                   capture_output=True, text=True, timeout=30)
    instrumented = source.read_text()
    assert 'vm_lava_pri_query_point(' in instrumented
    assert 'constexpr int constant(int value) { return value + 1; }' in instrumented
    assert 'template<class T> T identity(T value) { return value; }' in instrumented
    binary = tmp_path / 'native'
    compiled = subprocess.run([compiler, '-std=c++14', query_runtime_include, str(source), '-o', str(binary)],
                              capture_output=True, text=True, timeout=30)
    assert compiled.returncode == 0, compiled.stderr
    subprocess.run([str(binary)], check=True, timeout=10)


def test_c_queries_still_compile_and_preserve_results(tmp_path, query_runtime_include):
    tool = os.environ.get('LAVA_QUERY_TOOL') or shutil.which('lavaTool')
    compiler = shutil.which('clang-14')
    apply = shutil.which('clang-apply-replacements-14')
    if not tool or not compiler or not apply:
        pytest.skip('lavaTool and Clang 14 tools required')
    source = tmp_path / 'queries.c'
    source.write_text('''
int increment(int value) { return value + 1; }
int invoke(int (*callback)(int), int value) { return callback(value); }
int main(void) {
    int values[2] = {3, 4};
    int *cursor = values;
    int (*callback)(int) = increment;
    return invoke(callback, cursor[1]) != 5;
}
''')
    (tmp_path / 'compile_commands.json').write_text(json.dumps([{
        'directory': str(tmp_path), 'file': str(source),
        'arguments': [compiler, '-std=gnu11', '-c', str(source)],
    }]))
    subprocess.run([tool, '-action=query', '-p=' + str(tmp_path),
                    '-src-prefix=' + str(tmp_path), str(source)],
                   cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30)
    subprocess.run([apply, str(tmp_path)], cwd=tmp_path, check=True,
                   capture_output=True, text=True, timeout=30)
    instrumented = source.read_text()
    assert 'vm_lava_pri_query_point(' in instrumented
    assert '+ ({vm_lava_attack_point(' in instrumented  # Existing C probe form.
    binary = tmp_path / 'native'
    compiled = subprocess.run([compiler, '-std=gnu11', query_runtime_include, str(source), '-o', str(binary)],
                              capture_output=True, text=True, timeout=30)
    assert compiled.returncode == 0, compiled.stderr
    subprocess.run([str(binary)], check=True, timeout=10)
