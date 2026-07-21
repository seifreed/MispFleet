# CLAUDE.md

Instrucciones obligatorias para este proyecto. Tienen prioridad sobre cualquier comportamiento por defecto.

## Lenguaje

- Python **3.14** exclusivamente.

## Plataformas

- La librería debe funcionar en **Windows, Linux y macOS**, tanto **x64** como **ARM**, en las últimas versiones de cada sistema. Nada específico de una plataforma (rutas, APIs, dependencias) sin alternativa multiplataforma.

## Dependencias

- **Un único fichero de dependencias**: nada de separar `requirements.txt` y `requirements-dev.txt`. Todas las dependencias (runtime y desarrollo) van juntas en un solo sitio.

## Diseño

- **Clean Code**: funciones pequeñas y con una sola responsabilidad, nombres descriptivos, sin código muerto, sin imports sin usar, sin bloques comentados.
- **Clean Architecture**: la lógica de dominio no depende de infraestructura, UI ni frameworks. Depender de abstracciones, no de implementaciones concretas. No filtrar detalles de implementación entre capas. No introducir abstracciones prematuras.

## Quality Gate

Antes de dar por buena cualquier tarea, todo esto debe pasar **sin ningún error ni warning**:

- `black --check .`
- `ruff check .`
- `mypy .`

## Security Gate

También sin ningún error ni warning:

- `bandit -r .`
- `pip-audit`

## Prohibiciones

- **Está prohibido suprimir cualquier error, warning o policy.** Nada de `# noqa`, `# type: ignore`, `# nosec`, `--exit-zero`, exclusiones ni bajar la severidad para hacer pasar las gates. El código se arregla, no se silencia.

## Tests

- Tests de regresión y tests unitarios/de integración según corresponda.
- **Prohibido usar mocks** (nada de `unittest.mock`, `MagicMock`, `monkeypatch` ni stubs artificiales): los tests ejecutan código real.
- **Cobertura 100%** (`pytest --cov` con fallo por debajo del 100%).
- Antes de refactorizar debe existir cobertura del comportamiento actual.

## Git

- Hacer **commit y push en cada avance**.
- **No añadirse como co-author** en los commits (sin línea `Co-Authored-By`).
