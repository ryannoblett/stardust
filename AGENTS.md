# AGENTS.md

This file serves as a guide for agentic coding assistants working in this repository. It contains information about build commands, testing, code style, and conventions.

## Build and Development Commands

This repository is a Zig project. Before running any commands, ensure you have Zig installed on your system.

### Building the Project

```bash
zig build
```

This compiles the project using the build.zig build configuration and runs the default target (typically a release build).

### Development Builds

```bash
zig build -Doptimize=Debug
```

Build with debug symbols for development and testing.

### Running Tests

```bash
zig build test
```

Run all tests in the project.

### Running a Single Test

Use the test filter option to run a specific test:

```bash
zig build test -Dtest_filter="test_name"
```

Replace `test_name` with the actual name of the test you want to run.

### Formatting and Linting

Zig has built-in formatting:

```bash
zig fmt .
```

This will format all Zig files in the current directory and its subdirectories.

### Checking Style

There's no separate linter in Zig yet, but you can use the build system's `check` command:

```bash
zig build check
```

## Code Style Guidelines

### General Principles

- Follow standard Zig conventions and idioms
- Keep code clear and readable over clever optimizations
- Use descriptive names for variables, functions, and types
- Prefer explicit over implicit

### Imports

- Import only what you need
- Group imports in this order:
  1. Zig standard library imports
  2. External dependencies
  3. Local module imports

Example:
```zig
const std = @import("std");
const some_external = @import("some_external");
const local_module = @import("./local_module.zig");
```

### Formatting

- Use 4-space indentation (or tabs if the project prefers)
- Limit lines to 80-100 characters where reasonable
- Follow zig fmt output for all formatting decisions
- No trailing whitespace
- One blank line between function definitions
- Blank line after imports before first function/type definition

### Types and Naming

- Use PascalCase for type names (structs, enums, unions, error sets)
- Use camelCase for variables and functions
- Use snake_case for constants
- Use ALL_CAPS for global constants that are truly constant

Examples:
```zig
const PI = 3.14159;
const MAX_SIZE = 1024;

pub const MyStruct = struct {
    pub fn myFunction() void {
        const localVar = 42;
    }
};
```

### Error Handling

- Zig's error union approach is preferred:
```zig
pub fn divide(a: i32, b: i32) !i32 {
    if (b == 0) return error.DivisionByZero;
    return a / b;
}
```

- Define custom error sets for your module:
```zig
const Error = error{
    InvalidInput,
    OutOfRange,
    NotFound,
};
```

- When calling functions that return errors, handle them appropriately:
```zig
const result = try someFunction();
// or
const result = someFunction() catch |err| {
    return err;
};
```

- For APIs that should not fail, use `unreachable` where appropriate

### Memory Management

- Use Zig's allocators consistently
- Prefer stack allocation when possible
- Use ArenaAllocator for temporary allocations
- Always check allocation results
- Use proper ownership semantics

Example:
```zig
const allocator = std.heap.page_allocator;
const buffer = try allocator.alloc(u8, 1024);
defer allocator.free(buffer);
```

### Functions

- Keep functions small and focused (preferably under 50 lines)
- Document preconditions and postconditions in comments
- Use clear parameter names
- Try to keep function signatures on one line when possible
- Use multiple lines for complex signatures

### Comments

- Use /// for documentation comments (visible to zig doc)
- Use // for implementation comments
- Explain WHY, not WHAT
- Don't comment obvious code
- Keep line comments short

Documentation comment example:
```zig
/// Divides two integers, returning an error on division by zero
/// 
/// Preconditions:
///   - b must not be zero
/// 
/// Returns: a / b, or an error if b is zero
pub fn divide(a: i32, b: i32) !i32 {
    return a / b;
}
```

### Testing

Write comprehensive tests for all functions. Zig's test framework allows:

```zig
const std = @import("std");

test "my_function works correctly" {
    const result = my_function(input);
    try std.testing.expectEqual(result, expected);
}

test "my_function handles edge cases" {
    // Test edge cases
}
```

- Test normal cases
- Test edge cases and error conditions
- Test performance-critical code with benchmarks
- Use `try std.testing.expect(...)` for assertions

### Project Structure

- Organize code into logical modules
- Keep build.zig manageable (consider using build.zig.zon for dependencies)
- Use clear directory structure
- Prefix internal module names to avoid conflicts

### Documentation

- Document all public functions and types
- Use Zig's built-in documentation format
- Keep documentation up to date with the code
- Link to related functionality when appropriate

## Continuous Integration

This repository should use CI to:
- Build on multiple platforms
- Run tests
- Check formatting
- Verify builds with different Zig versions

Sample .github/workflows/ci.yml:
```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        zig: [0.11, master]
    steps:
      - uses: actions/checkout@v4
      - uses: korple ActionSetupZig@v1
        with:
          zig-version: ${{ matrix.zig }}
      - name: Build
        run: zig build
      - name: Test
        run: zig build test
      - name: Format check
        run: zig fmt --check .
```

## Common Pitfalls

1. **Error handling**: Remember that `try` only works in functions that return an error union. In void functions, you'll need to use `catch` or propagate differently:
```zig
if (result) |err| {
    return err;
}
```

2. **Memory leaks**: Use `defer` appropriately for cleanup:
```zig
const data = allocator.alloc(u8, size) catch unreachable;
defer allocator.free(data);
```

3. **Bounds checking**: Always check array bounds before access:
```zig
if (index >= array.len) return error.OutOfBounds;
```

4. **Type safety**: Zig is strictly typed. Use @intCast, @ptrCast, @bitCast, and @intToPtr carefully.

5. **Build system**: The build.zig file uses Build.step, Build.Module, and other Build types. Remember that build scripts run at compile time, not runtime.

## Performance Considerations

- Use `@compileTime` for expensive computations that can be done at compile time
- Prefer stack allocation for small, short-lived data
- Use `@inline` judiciously for critical path functions
-profile-generated code with -Dprofile=true flag
- Use `unreachable` for code paths that should never be taken
