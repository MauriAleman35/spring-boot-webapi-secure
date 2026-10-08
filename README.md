# Spring Boot DevSecOps Lab

Aplicacion deliberadamente vulnerable para prácticas controladas de SAST, SCA,
secret scanning, análisis de contenedores y DAST.

> **Advertencia:** ejecutar únicamente en `localhost` o en una red de laboratorio
> aislada. No desplegar en Internet ni reutilizar credenciales reales.

## Requisitos

- JDK 21
- Maven 3.9+
- Docker, opcional
- Semgrep, para el análisis local

## Iniciar la aplicación

```bash
mvn clean verify
mvn spring-boot:run
```

La aplicación estará disponible en `http://localhost:8080`.

## Endpoints del laboratorio

```text
GET  /api/products/search?name=Laptop
POST /api/comments/preview
GET  /api/admin/users/1
POST /api/auth/login
```

Ejemplo para la vista previa:

```bash
curl -X POST http://localhost:8080/api/comments/preview \
  -H "Content-Type: application/json" \
  -d '{"comment":"Comentario de prueba"}'
```

Ejemplo de autenticación:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"usuario","password":"prueba"}'
```

## Semgrep local

```bash
semgrep scan --config auto --config .semgrep.yml src/main/java
```

El docente dispone de `docs/GUIA-DOCENTE.md`, que contiene el catálogo de
hallazgos y las pruebas sugeridas. Se recomienda entregar inicialmente a los
estudiantes el resto del repositorio sin dicho documento.

## DevSecOps Pipeline
- SAST con Semgrep y SpotBugs
- SCA con OWASP Dependency-Check y CycloneDX SBOM
- Quality Gate activo para bloquear vulnerabilidades criticas

