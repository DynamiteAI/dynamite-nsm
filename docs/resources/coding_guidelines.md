# Coding Guidelines

## Language

Internally, we use a `Python3.7` development environment on `Ubuntu 20.04`.

## Styles

### Overriding Principle

Names that are visible to the user as public parts of the API should follow conventions that reflect usage rather than implementation.

| Style                         | Language Internals              |
|-------------------------------|---------------------------------|
| `UPPERCASE`                   | constants                       |
| `lower_case_with_underscores` | methods, functions, and modules |
| `CapitalizedWords`            | classes                         |

### Tabs or Spaces

Always use **spaces** instead of tabs.

### Indention
Each indention should be **4 spaces**.

### Maximum Line Length
The maximum **120** characters.

### Blank lines

| Number of Blank Lines After | Language Internals |
|-----------------------------|--------------------|
| 2                           | function           |
| 1                           | method             |
| 2                           | import statement   |


### Other Styling Stuff

In general, follow PEP-8 guidelines [outlined here](https://www.python.org/dev/peps/pep-0008/#naming-conventions).

Use a tool like [flake8](https://flake8.pycqa.org/en/latest/) to improve readability.

## Doc Strings

1. All methods and functions should document their parameters and return types.
3. [Google Style](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html)
4. [Type-hints](https://docs.python.org/3/library/typing.html) should be added to all method and function parameters.

## Third-Party Dependencies

We love open-source software, but a poorly maintained project merged into the `main` branch can create
technical debt down the line. If you have a third party dependency make sure it is well maintained.