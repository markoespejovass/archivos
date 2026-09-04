# Guía de remediación para el Ethical Hacking

**Anexo de `SECURITY_CODE_REVIEW.md` v1.7** · 2026-09-04
**Para:** el desarrollador que va a aplicar los cambios.
**Alcance:** solo los hallazgos que se pueden cerrar **con alta confianza** sin decisiones de arquitectura ni de producto.

---

## Antes de empezar: lee estas cinco líneas

1. **Esto no hace que el EH salga limpio.** Lo decide **SEC-002 (BOLA)**, que no está aquí porque no se puede cerrar sin saber qué claim del token de Cognito identifica al cliente. Ver §0.
2. **Los números de línea son de la entrega del 3-sep** y se moverán en cuanto apliques el primer cambio. **Localiza por el fragmento de código, no por la línea.**
3. Los controladores se generan con `openapi-generator` en tiempo de compilación. **Tocar un `.yaml` de contrato regenera clases**: recompila entero, no incremental.
4. Cada ficha trae **Verificación**. Si no puedes ejecutarla, el cambio no está terminado.
5. **Ningún cambio de esta guía toca `cpe-nxhbsc-becustombeprogrm` ni `cpe-nxhbsc-lmauthorizer`**, que están aplazados (§1.1 del informe).

---

## §0. Lo que esta guía NO cierra, y por qué importa

| Hallazgo | Por qué no está aquí |
| -------- | -------------------- |
| **SEC-002 — BOLA** | Requiere saber **qué claim del token de Cognito lleva el identificador del cliente**. No hay ni una referencia a Cognito, `issuer-uri`, `JwtDecoder` ni JWKS remoto en los 682 ficheros. Es una pregunta a Arquitectura, no una tarea de código |
| SEC-001 — autenticación desactivada | Mismo bloqueo. Además el gateway lo enmascara (§22) |
| SEC-019 — rate limiting | Decisión de dónde vive el control: gateway o aplicación |
| SEC-021 — endpoint interno publicado | Decisión de configuración del API Gateway |
| SEC-010 — fail-open en `beclaims` | Quitar el mock cambia lo que ve el cliente cuando Contáctanos cae. **Necesita visto bueno de producto** |
| SEC-040 — `"Match Found"` constante | Hace falta el mapeo real de estados de Gesintel |
| SEC-015 — clave S3 con datos del cliente | Afecta a objetos ya almacenados: necesita plan de migración |

> **La consecuencia práctica.** Aplicando toda esta guía, el proveedor dejará de reportar unos nueve casos de prueba. Pero **CP-01 y CP-18 seguirán saliendo**, y con ellos API1 (Broken Object Level Authorization) en Critical o High. Si el objetivo es un informe sin hallazgos graves, la conversación con Arquitectura sobre el claim del token es el camino crítico, no esta guía.

---

## Plan de trabajo sugerido

Cuatro PR, en este orden. El primero es el que más quita del informe del proveedor por unidad de esfuerzo.

| PR | Contenido | Hallazgos | Esfuerzo |
| -- | --------- | --------- | -------- |
| **PR-1 · Exposición de datos** | Fichas 1 a 4 | SEC-048, SEC-058, SEC-039, SEC-047 | ~4 h |
| **PR-2 · Superficie y errores** | Fichas 5 a 9 | SEC-032, SEC-028, SEC-046, SEC-052, SEC-018 | ~6 h |
| **PR-3 · Configuración** | Fichas 10 a 13 | SEC-022, SEC-025, SEC-029, SEC-020, SEC-044 | ~3 h |
| **PR-4 · Higiene de logs y código muerto** | Fichas 14 a 17 | SEC-005 (parcial), SEC-011, SEC-012, SEC-013, SEC-035, SEC-041 | ~2 h |

---

# PR-1 · Exposición de datos

## Ficha 1 — SEC-048 · El DNI del titular sale en los resultados de búsqueda

**Severidad:** Medium · **Esfuerzo:** 10 min · **Riesgo del cambio:** bajo · **Caso EH:** CP-03

### Dónde

```text
cpe-nxhbsc-bedocmanagement/src/main/java/.../infrastructure/adapters/output/DocumentMapper.java
Método: searchMapper(List<FileEntity>)   · líneas 44-55
```

### Qué pasa

`FileEntity.name` **no contiene el nombre del documento**: contiene el `ownerId`, es decir el DNI del titular. Lo fija `toEntity` (líneas 78-82). `getMapper` ya se corrigió en la entrega del 3-sep; `searchMapper` se quedó sin corregir.

### Código actual

```java
public WrapperPostSearchDocumentsResponse searchMapper(List<FileEntity> objectListing){
    WrapperPostSearchDocumentsResponse response = new WrapperPostSearchDocumentsResponse();
    List<WrapperMySearchDocumentResponse> documents = objectListing.stream().map(objectSumary ->{
        WrapperMySearchDocumentResponse wrapper = new WrapperMySearchDocumentResponse();
        wrapper.setDocumentId(objectSumary.getCustomerId());
        wrapper.setName(objectSumary.getName());          // <-- getName() es el DNI del titular
        wrapper.setMimeType(objectSumary.getMimeType());
        return wrapper;
    }).collect(Collectors.toList());
    response.setDocuments(documents);
    return response;
}
```

### Código nuevo

```java
        wrapper.setName(objectSumary.getFileName());       // el nombre real del fichero
```

Es la misma corrección que ya se aplicó en `getMapper` (línea 113). Un solo `getName()` → `getFileName()`.

### Verificación

```bash
curl -s -X POST "$BASE/v2/document_management/search_documents" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"searchParameters":{"discriminator":"OR","searchProperties":[{"keyId":"STATUS","keyOperator":"EQUAL","keyValue":"uploaded"}]}}'
```

En la respuesta, `documents[].name` debe traer un nombre de fichero (`contrato.pdf`), **no un número de documento de 8 dígitos**.

> **Ojo con el efecto colateral.** Si algún consumidor está usando hoy `name` como si fuera el DNI, se le rompe. Búscalo antes de mergear: es un cambio correcto, pero no es invisible.

---

## Ficha 2 — SEC-058 · `search_documents` devuelve el inventario completo

**Severidad:** High · **Esfuerzo:** 30 min · **Riesgo del cambio:** bajo · **Caso EH:** CP-18 *(el de mayor valor de la lista)*

### Dónde

```text
cpe-nxhbsc-bedocmanagement/src/main/java/.../infrastructure/adapters/output/jpa/FileSearchMapper.java
Método: toSearch(WrapperMySearchFilterRequest)  · líneas 15-49
```

### Qué pasa

El operador `CONTAINS` se traduce a `contains(attr, :valor)` de DynamoDB. **`contains(attr, "")` es cierto para toda cadena**, así que con `keyValue: ""` el filtro no filtra y el `Scan` devuelve la tabla entera. El valor no se valida en ningún punto.

### Código actual

```java
for (WrapperMySearchFilterRequestSearchPropertiesInner prop : request.getSearchProperties()) {
    String keyId = prop.getKeyId();
    if(keyId == null){ keyId = "0"; }
    String field = mapField(keyId);
    ...
    Object value = castValue(keyId, prop.getKeyValue());   // <-- el valor no se valida
    if (value == null){ value = prop.getKeyValue(); }
```

### Código nuevo

Añade la validación antes de construir la condición:

```java
private static final int MIN_LONGITUD_BUSQUEDA = 3;

// dentro del bucle, justo despues de obtener keyOperator:
String raw = prop.getKeyValue();
if (raw == null || raw.isBlank()) {
    throw new BadRequestException("criterio_vacio",
            "El valor de busqueda no puede estar vacio");
}
if (keyOperator == WrapperMySearchFilterRequestSearchPropertiesInner.KeyOperatorEnum.CONTAINS
        && raw.trim().length() < MIN_LONGITUD_BUSQUEDA) {
    throw new BadRequestException("criterio_demasiado_corto",
            "Una busqueda por coincidencia parcial requiere al menos "
                    + MIN_LONGITUD_BUSQUEDA + " caracteres");
}
```

`BadRequestException` es `com.santander.framework.springboot.core.exceptions.BadRequestException`, la misma que ya usan `UploadDocumentValidator` y `DownloadDocumentValidator`.

### Verificación

```bash
# debe devolver 400, no 200 con todos los documentos
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/v2/document_management/search_documents" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"searchParameters":{"discriminator":"OR","searchProperties":[{"keyId":"NAME","keyOperator":"CONTAINS","keyValue":""}]}}'
```

> **Esto es una mitigación, no la solución.** Sigue siendo posible barrer el espacio por prefijos de tres caracteres. Lo que cierra el hallazgo de verdad es filtrar por titular, y eso depende de SEC-002 (§0). El valor real de este cambio es convertir un volcado silencioso de una petición en una campaña ruidosa y detectable.

---

## Ficha 3 — SEC-039 · El `Scan` no tiene tope

**Severidad:** Medium · **Esfuerzo:** 20 min · **Riesgo del cambio:** medio · **Caso EH:** CP-08

### Dónde

```text
cpe-nxhbsc-bedocmanagement/src/main/java/.../infrastructure/config/BaseDynamoRepository.java
Método: search(FileSearch)  · líneas 76-92
```

### Qué pasa

`ScanEnhancedRequest` sin `limit`: el coste en RCU es proporcional al tamaño **de la tabla**, no al del resultado. El `filterExpression` se aplica *después* de leer.

### Código actual

```java
public List<T> search(FileSearch search) {
    ExpressionBuilder builder = new ExpressionBuilder();
    Expression expression = builder.build(search);

    ScanEnhancedRequest request = ScanEnhancedRequest.builder()
            .filterExpression(expression)
            .build();

    List<T> results = new ArrayList<>();
    table.scan(request).items().forEach(results::add);
    return results;
}
```

### Código nuevo

```java
private static final int MAX_RESULTADOS = 100;

public List<T> search(FileSearch search) {
    ExpressionBuilder builder = new ExpressionBuilder();
    Expression expression = builder.build(search);

    ScanEnhancedRequest request = ScanEnhancedRequest.builder()
            .filterExpression(expression)
            .limit(MAX_RESULTADOS)          // items evaluados por pagina
            .build();

    List<T> results = new ArrayList<>();
    for (T item : table.scan(request).items()) {
        results.add(item);
        if (results.size() >= MAX_RESULTADOS) {
            break;                          // corta el recorrido de paginas
        }
    }
    return results;
}
```

> **Los dos topes hacen falta y no son el mismo.** `.limit()` acota los ítems que DynamoDB evalúa **por página**; el `break` acota cuántas páginas recorre el iterador. Con `.limit()` solo, el SDK sigue pidiendo páginas hasta agotar la tabla y no habrás arreglado nada.

### Verificación

Sube 150 documentos en un entorno de pruebas y lanza una búsqueda que los case a todos: la respuesta debe traer 100.

> **Antes de mergear**, comprueba que ningún consumidor dependa de recibir el conjunto completo. Si hace falta más, lo correcto es exponer paginación en el contrato (`cursor` + `limit`), no subir la constante.

---

## Ficha 4 — SEC-047 · Enumeración por respuestas distintas

**Severidad:** High · **Esfuerzo:** 45 min · **Riesgo del cambio:** bajo · **Caso EH:** CP-02

### Dónde

```text
cpe-nxhbsc-bedocmanagement/src/main/java/.../infrastructure/adapters/output/DocumentManagementAdapter.java
  downloadDocument(...)        · lineas 62-72     -> NotFoundException(Constant.NOT_FOUND_CODE, ...)
  getDocument(String)          · lineas 179-186   -> NotFoundException(Constant.NOT_FOUND_CODE, ...)
  downloadDocumentIntern(...)  · lineas 241-261   -> NotFoundException("documento_no_encontrado", ...)
```

### Qué pasa

Tres endpoints responden **distinto** ante el mismo identificador inexistente. Dos usan el código de `Constant` y el tercero un literal propio; además `downloadDocumentIntern` devuelve `null` (→ 200 vacío) cuando falta el campo `document`. La diferencia permite distinguir qué identificadores existen sin acceder a ellos.

### Código nuevo

**(a)** En `downloadDocumentIntern`, sustituye el literal por la constante compartida:

```java
if(fileEntity.isEmpty()) {
    throw new NotFoundException(Constant.NOT_FOUND_CODE, Constant.NOT_FOUND_TEXT);
}
```

**(b)** Elimina las dos ramas que devuelven `null` al principio del método:

```java
if(criteria.getDocument() == null) { return null; }              // <-- borrar
...
if(documentResponse.getDocumentId() == null) { return null; }    // <-- borrar
```

Son código muerto: `DocumentManagementInputPort.postDownloadDocumentIntern` ya llama a `documentValidator.validate(criteria)`, que lanza `BadRequestException` en ambos casos. Dejarlas solo garantiza que algún día alguien reintroduzca el 200 vacío.

### Verificación

```bash
for ep in download_document download_document_intern; do
  curl -s -o /dev/null -w "$ep -> %{http_code}\n" -X POST "$BASE/v2/document_management/$ep" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"document":{"documentId":"00000000-0000-0000-0000-000000000000"}}'
done
curl -s -o /dev/null -w "metadata -> %{http_code}\n" \
  "$BASE/v2/document_management/documents/00000000-0000-0000-0000-000000000000" \
  -H "Authorization: Bearer $TOKEN"
```

Los tres deben devolver **404 con el mismo cuerpo**. Compara también los cuerpos, no solo el código.

---

# PR-2 · Superficie y errores

## Ficha 5 — SEC-032 · Backdoor de pruebas en la ruta productiva

**Severidad:** Medium · **Esfuerzo:** 20 min · **Riesgo del cambio:** bajo · **Caso EH:** CP-15

### Dónde

```text
cpe-nxhbsc-bedigitsignature/src/main/java/.../infrastructure/adapters/output/client/DocumentClient.java
Método: getDocument(String)  · lineas 34-46
Recurso: src/main/resources/test.pdf
```

### Código actual

```java
public Mono<String> getDocument(String documentId) {
    log.info("antes en obtener document, documentId: {}", documentId);
    if(documentId.equals("CONTRATO_CLIENTE")){          // <-- valor magico
        try {
            ClassPathResource resource = new ClassPathResource("test.pdf");
            byte[] pdfBytes = resource.getInputStream().readAllBytes();
            String fileBase64 = Base64.getEncoder().encodeToString(pdfBytes);
            return Mono.just(fileBase64);
        } catch (Exception ex){
            return Mono.empty();
        }
    }
    return documentWebClient
```

### Código nuevo

Borra el bloque `if` completo (líneas 37-46) y el fichero `src/main/resources/test.pdf`. El método debe empezar directamente por `return documentWebClient`.

### Verificación

```bash
curl -s -X POST "$BASE/v1/signature/signer" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"nombre":"X","apellido":"Y","dni":"00000000","documentos":[{"idDocumento":"CONTRATO_CLIENTE","page":1,"position":"1"}]}'
```

Debe responder error de documento no encontrado, **no** un flujo de firma correcto. Comprueba además que `test.pdf` no está en el JAR: `unzip -l target/*.jar | grep test.pdf` no debe devolver nada.

---

## Ficha 6 — SEC-028 · Excepciones no controladas devuelven 500

**Severidad:** Medium · **Esfuerzo:** 2 h · **Riesgo del cambio:** bajo · **Caso EH:** CP-09

### Dónde

Cinco proyectos **sin ningún `@RestControllerAdvice`**:

```text
cpe-nxhbsc-beclaims
cpe-nxhbsc-bedigitsignature
cpe-nxhbsc-bedocmanagement
cpe-nxhbsc-beemailboxes
cpe-nxhbsc-beknowyocustomer
```

Y los seis que sí lo tienen no declaran `@ExceptionHandler(Exception.class)`, así que tampoco cubren lo inesperado.

### Qué pasa

Entradas límite provocan excepciones que nadie mapea, y el consumidor recibe un 500 con el detalle que decida el framework. Ejemplos reales del código:

| Entrada | Dónde revienta | Excepción |
| ------- | -------------- | --------- |
| `keyId: "VERSION"`, `keyValue: "abc"` | `FileSearchMapper.castValue` | `NumberFormatException` |
| `keyId` no válido | `FileSearchMapper.mapField` | `IllegalArgumentException` |
| `recipients.to` como lista vacía | `EmailboxIdInputPort:55` | `IndexOutOfBoundsException` |
| Respuesta del proveedor sin `scanReference` | `BiometricInputPort:378` | `NullPointerException` |

### Código nuevo

Un `@RestControllerAdvice` por proyecto, en el paquete `infrastructure.adapters.input.advice`:

```java
@Slf4j
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE)          // se aplica solo si nadie mas lo maneja
public class UnhandledExceptionAdvice {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
        String ref = UUID.randomUUID().toString();
        log.error("Error no controlado. ref={}", ref, ex);   // el detalle, solo al log

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("errors", List.of(Map.of(
                        "code", "TL9999",
                        "level", "error",
                        "message", "Error interno",
                        "description", "ref=" + ref))));      // al consumidor, solo la referencia
    }
}
```

**`@Order(Ordered.LOWEST_PRECEDENCE)` no es opcional.** Sin él, este handler se pone por delante de los del framework Gluon y de los `BusinessException` existentes, y convertirías todos los 400 y 404 en 500.

### Antes de darlo por bueno

**Contrasta el cuerpo con el envelope real de tu entorno.** Estos proyectos usan `santander.core.exceptions.error-format: GLUON`, y la forma exacta del envelope la impone el framework. Provoca un 400 real (por ejemplo, un `documentId` vacío), copia la estructura que devuelve y ajusta el `Map` para que coincida. Un 500 con una forma distinta a la de los demás errores es un hallazgo nuevo, no una corrección.

### Verificación

```bash
curl -s -X POST "$BASE/v2/document_management/search_documents" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"searchParameters":{"discriminator":"AND","searchProperties":[{"keyId":"VERSION","keyOperator":"EQUAL","keyValue":"abc"}]}}'
```

Debe devolver un envelope con `TL9999` y una referencia — **sin traza, sin nombre de clase, sin mensaje de la excepción**.

---

## Ficha 7 — SEC-046 y SEC-052 · Cinco operaciones declaradas que responden 501

**Severidad:** Low / Info · **Esfuerzo:** 1 h · **Riesgo del cambio:** medio · **Caso EH:** CP-12

### Qué pasa

Están en el contrato, el gateway puede publicarlas, y responden `501 Not Implemented`. Para un pentester es un mapa de lo que viene.

| Operación | Contrato | Línea |
| --------- | -------- | ----: |
| `PUT /documents/{document_id}` (`documentDetails`) | `bedocmanagement/openapi.yaml` | 68 |
| `POST /documents/{document_id}/consolidate` (`consolidateDocument`) | `bedocmanagement/openapi.yaml` | 105 |
| `POST /update_document` (`updateDocumentVersion`) | `bedocmanagement/openapi.yaml` | 344 |
| `GET /create` (`getKycInformation`) | `beknowyocustomer/openapi.yaml` | 105 |
| `GET /health` (`retrieveHealth`) | `beemailboxes/openapi.yaml` | 42 |

### Qué hacer

Elimina esas operaciones del `paths:` de cada contrato y recompila. Si el `delegate` implementaba el método solo para delegar en el `super` (como `HelloApiDelegateImpl.getKycInformation` en `beknowyocustomer`, línea 33), borra también el método.

**Excepción a valorar:** `GET /health` en `beemailboxes` probablemente se declaró por copia de la plantilla. Si el healthcheck real es el de Actuator, quítalo del contrato; si alguien lo consume, impleméntalo. Lo que no puede quedarse es declarado y devolviendo 501.

### Verificación

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X PUT "$BASE/v2/document_management/documents/abc" -H "Authorization: Bearer $TOKEN"
```

Debe devolver **404 o 405**, nunca 501. Y `GET /v3/api-docs` no debe listar ya esas operaciones.

---

## Ficha 8 — SEC-018 (b) · El error del proveedor llega al consumidor

**Severidad:** Medium · **Esfuerzo:** 45 min · **Riesgo del cambio:** bajo · **Caso EH:** CP-13

### Dónde

```text
cpe-nxhbsc-bedigitsignature/src/main/java/.../infrastructure/utils/Util.java           · lineas 12-24
cpe-nxhbsc-bedigitsignature/src/main/java/.../adapters/output/DocumentProcessService.java · lineas 146-152
```

### Qué pasa

`Util.handleError` mete el cuerpo del proveedor en el mensaje de la excepción, y `buildUniqueResponse` lo publica en `errorDTO.description`. La mitad de `becustombeprogrm` ya se corrigió con el patrón bueno; esta no.

### Código actual

```java
// Util.java
return response -> response.bodyToMono(String.class)
        .defaultIfEmpty("")
        .flatMap(body -> Mono.error(
                new SantanderException(
                        String.format("%s. Status=%s, body=%s", message, response.statusCode(), body))));
```

```java
// DocumentProcessService.java:146-152
errorDTO.setDescription(result);      // result = error.getMessage() -> "... Status=..., body=..."
```

### Código nuevo

```java
// Util.java  -- el detalle al log, al consumidor solo la referencia
public static Function<ClientResponse, Mono<? extends Throwable>> handleError(String message) {
    return response -> response.bodyToMono(String.class)
            .defaultIfEmpty("")
            .flatMap(body -> {
                String ref = UUID.randomUUID().toString();
                log.error("{}. ref={}, status={}, body={}", message, ref, response.statusCode(), body);
                return Mono.error(new SantanderException(message + ". ref=" + ref));
            });
}
```

`Util` es hoy una clase sin logger: añade `@Log4j2` (es el que ya usa el resto del proyecto).

### Verificación

Fuerza un error del proveedor de firma (URL inválida en el perfil de pruebas) y comprueba que la respuesta trae `TL9999` y una referencia, **sin `Status=` ni `body=`**. Esa referencia debe aparecer en el log del pod.

---

# PR-3 · Configuración

## Ficha 9 — SEC-022 · Actuator sin autenticación y con detalle completo

**Severidad:** High · **Esfuerzo:** 30 min · **Riesgo del cambio:** bajo

### Dónde

`src/main/resources/config/application.yml` de **los 10 proyectos en alcance**. Ejemplo en `bedocmanagement`, líneas 61-63.

### Código actual

```yaml
management:
  endpoint.health:
    show-details: ALWAYS
```

### Código nuevo

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info          # lista blanca explicita
  endpoint:
    health:
      show-details: when-authorized
      probes:
        enabled: true                 # /health/liveness y /health/readiness para k8s
```

`show-details: ALWAYS` publica hoy el detalle de cada componente de salud: motores de base de datos, endpoints de terceros y sus estados. Es reconocimiento gratis. `when-authorized` lo reserva a peticiones autenticadas y deja el `status` agregado para las sondas.

### Verificación

```bash
curl -s "$BASE/actuator/health" -H "Authorization: Bearer $TOKEN" | head -c 200
curl -s -o /dev/null -w '%{http_code}\n' "$BASE/actuator/env"
```

El primero debe traer `{"status":"UP"}` sin el bloque `components`; el segundo, 404.

> Comprueba que las sondas de Kubernetes siguen en verde tras el despliegue. Si apuntan a `/actuator/health`, siguen funcionando; si esperaban el detalle, actualízalas a `/health/liveness` y `/health/readiness`.

---

## Ficha 10 — SEC-025 · Swagger y `api-docs` activos en todos los perfiles

**Severidad:** Low · **Esfuerzo:** 20 min · **Riesgo del cambio:** bajo

### Qué hacer

En los `application-pro.yml`, `application-pre.yml` y `application-cert.yml` de los 10 proyectos:

```yaml
springdoc:
  api-docs:
    enabled: false
  swagger-ui:
    enabled: false
```

El bloque `springdoc` de `application.yml` (líneas 69-72 en `bedocmanagement`) se queda como está: sirve para `local`.

### Verificación

Con el perfil `pro` activo, `GET /v3/api-docs` y `GET /swagger-ui.html` deben devolver 404.

> El gateway no publica estas rutas, así que esto **no cierra un vector desde Internet**: cierra el acceso desde el plano lateral, que es el escenario de SEC-021.

---

## Ficha 11 — SEC-029 · `ddl-auto: update` y `sql.init.mode: always` en producción

**Severidad:** Medium · **Esfuerzo:** 10 min · **Riesgo del cambio:** **alto — leer la nota**

### Dónde

```text
cpe-nxhbsc-beproducoffering/src/main/resources/config/application-pro.yml  · lineas 26-32
```

### Código actual

```yaml
  jpa:
    database-platform: org.hibernate.dialect.PostgreSQLDialect
    hibernate:
      ddl-auto: update
    defer-datasource-initialization: true
  sql:
    init:
      mode: always
```

### Código nuevo

```yaml
  jpa:
    database-platform: org.hibernate.dialect.PostgreSQLDialect
    hibernate:
      ddl-auto: validate
    defer-datasource-initialization: false
  sql:
    init:
      mode: never
```

`becreditrisk` ya usa `ddl-auto: validate` en su perfil `pro`: copia ese patrón.

> **Por qué el riesgo es alto y no bajo.** Con `validate`, si el esquema real no coincide con las entidades **la aplicación no arranca**. Eso es lo correcto —es justamente lo que `update` estaba ocultando— pero significa que debes verificarlo en `pre` antes de tocar `pro`. Y `mode: always` implica que hoy hay un `data.sql` ejecutándose en cada arranque: mira qué contiene antes de desactivarlo, no vaya a ser que algo dependa de él.

---

## Ficha 12 — SEC-020 · Payloads base64 sin límite

**Severidad:** High · **Esfuerzo:** 1 h · **Riesgo del cambio:** medio

### Qué pasa

Los límites de multipart **no aplican** a un base64 dentro de un JSON. Hoy nada acota el tamaño, y `UploadDocumentValidator` decodifica el contenido íntegro en memoria (y `DocumentManagementAdapter` lo vuelve a decodificar: dos copias del fichero en heap por petición).

### Qué hacer

**(a) En los contratos**, añade `maxLength` a los campos base64. Un documento de 10 MB son ~13,4 M de caracteres:

```yaml
        folderReference:
          type: string
          maxLength: 14000000        # ~10 MB en base64
          description: ...
```

Ficheros y líneas: `bedocmanagement/openapi.yaml` (808, 911, 1088, 1183) y `beidentbiometric/api/biometricapi.yaml` (`templateRaw` 1205 y 1225, `imageBuffer` 1256).

**(b) En `application.yml`** de los proyectos que reciben base64, acota también el cuerpo:

```yaml
server:
  max-http-request-header-size: 128KB
  tomcat:
    max-http-form-post-size: 15MB
    max-swallow-size: 15MB
spring:
  codec:
    max-in-memory-size: 15MB        # para los WebClient reactivos
```

**(c) En `UploadDocumentValidator`**, valida el tamaño **antes** de decodificar:

```java
private static final int MAX_BASE64_CHARS = 14_000_000;

if (base64Content.length() > MAX_BASE64_CHARS) {
    throw new BadRequestException("archivo_demasiado_grande",
            "El contenido supera el tamano maximo permitido");
}
```

El orden importa: comprobar `length()` es O(1); decodificar y luego medir ya te ha costado la memoria que querías evitar.

### Verificación

Envía un `folderReference` de 20 MB: debe responder 400 y el pod no debe reiniciarse por OOM.

---

## Ficha 13 — SEC-044 · Cabeceras inadecuadas para una API JSON

**Severidad:** Low · **Esfuerzo:** 30 min · **Riesgo del cambio:** bajo

### Dónde

`SecurityConfig.java` de los 10 proyectos. Ejemplo en `beclaims`, líneas 43-50.

### Código actual

```java
.headers(headers -> headers.contentSecurityPolicy(
        csp -> csp.policyDirectives("default-src 'self'; script-src 'self'; object-src 'none';")));
```

Una CSP con `script-src` en una API que solo devuelve JSON no protege de nada: no hay documento que ejecute scripts. Faltan, en cambio, las que sí aplican.

### Código nuevo

```java
.headers(headers -> headers
        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
        .frameOptions(frame -> frame.deny())
        .contentTypeOptions(Customizer.withDefaults())          // X-Content-Type-Options: nosniff
        .referrerPolicy(rp -> rp.policy(ReferrerPolicy.NO_REFERRER))
        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000)));
```

`nosniff` es el que importa aquí: `bedocmanagement` devuelve contenido con el `Content-Type` que declaró el cliente (SEC-015), y sin esa cabecera el navegador puede interpretarlo por su cuenta.

---

# PR-4 · Higiene de logs y código muerto

## Ficha 14 — SEC-005 (parcial) · La validación de OTP acepta cualquier código

**Severidad:** Critical *(el hallazgo no se cierra con esto — lee la nota)* · **Esfuerzo:** 2 min · **Caso EH:** CP-16

### Dónde

```text
cpe-nxhbsc-beemailboxes/src/main/java/.../infrastructure/adapters/output/OTPServiceAdapter.java
Método: validCode(String, WrapperRequestClassifyEmails)  · lineas 61-71
```

### Qué pasa

`JsonApiClient.validOTP` ya se corrigió y devuelve `"Valid"` o `"Invalid"` según el veredicto real de Celmedia. Pero el llamante **sigue comprobando `!= null`**, y como el método nunca devuelve `null`, la rama de error es código muerto: **cualquier OTP responde `PROCESSED`**.

### Código actual

```java
String status = jsonApiClient.validOTP(generateValidateOtp(otp));

if (status != null) {
    return generateResponsseValidCode(StatusInfo.StatusCodeEnum.PROCESSED);
} else {
    return generateResponsseValidCode(StatusInfo.StatusCodeEnum.ERROR);
}
```

### Código nuevo

```java
String status = jsonApiClient.validOTP(generateValidateOtp(otp));

if ("Valid".equals(status)) {
    return generateResponsseValidCode(StatusInfo.StatusCodeEnum.PROCESSED);
}
return generateResponsseValidCode(StatusInfo.StatusCodeEnum.ERROR);
```

### Verificación

```bash
curl -s -X POST "$BASE/v1/emailboxes/otp/emails/00000000/classify_email" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
```

Con un código inexistente debe devolver `ERROR`. **Añade un test que envíe un OTP incorrecto y exija `ERROR`**: es el que habría detectado que la corrección anterior quedó inerte.

> **Lo que este cambio NO arregla, y conviene decirlo en el PR.** La búsqueda sigue siendo `repository.getByKey(otp, null)` con **el OTP como partition key**, así que un OTP válido *de otro usuario* sigue superando la validación. Eso es BOLA otra vez (§0) y necesita vincular el código a la sesión o al destinatario. Tampoco hay TTL ni marca de consumo: un OTP generado hoy sigue siendo válido indefinidamente y es reutilizable. **SEC-005 sigue abierto como Critical después de este cambio**; lo que se cierra es que un código *incorrecto* pase.

---

## Ficha 15 — SEC-011, SEC-012 y SEC-007 · Datos sensibles en los logs

**Severidad:** High / Medium · **Esfuerzo:** 15 min · **Riesgo del cambio:** ninguno

Borra estas líneas. No hay sustituto: ninguna aporta nada que no esté ya en la traza.

| Proyecto | Fichero:línea | Qué escribe |
| -------- | ------------- | ----------- |
| bedigitsignature | `DocumentClient.java:80` | **El PDF completo en base64** |
| beidentbiometric | `FacephiAdapter.java:130` | El `tokenOcr` (DTO con `@Data`) |
| beemailboxes | `OTPServiceAdapter.java:101` | **El OTP en claro** |
| beemailboxes | `OTPServiceAdapter.java:116` | El `RequestOTP` completo: OTP + destinatario |
| beemailboxes | `XmlApiClient.java:44` | El XML íntegro enviado a Celmedia, con el OTP |
| beemailboxes | `XmlApiClient.java:47` | La respuesta íntegra del proveedor |

Si necesitas trazabilidad, registra un identificador de correlación, nunca el contenido:

```java
log.info("OTP generado para la transaccion {}", uuid);   // en vez de log.info("OTP generado: {}", otp)
```

> **Sobre `FacephiAdapter`:** las otras trece llamadas `log.warn("request ...: {}", request)` **no filtran** porque sus DTO no tienen `@Data` ni `@ToString` (§14 del informe). Aun así, elimínalas o cámbialas por un identificador: hoy no imprimen nada útil, y el día que alguien añada `@Data` a uno de esos DTO pasan a volcar plantillas faciales sin que ninguna revisión lo note.

---

## Ficha 16 — SEC-013 · `wiretap(true)` vuelca el tráfico HTTP completo

**Severidad:** High · **Esfuerzo:** 20 min · **Riesgo del cambio:** ninguno

Quita `.wiretap(true)` en los **cinco proyectos en alcance**:

```text
cpe-nxhbsc-beclaims          WebClientConfig.java:65
cpe-nxhbsc-becreditrisk      WebClientConfig.java:84
cpe-nxhbsc-bedigitsignature  WebClientConfig.java:89
cpe-nxhbsc-beidentbiometric  WebClientConfig.java:64
cpe-nxhbsc-bewatchscreening  WebClientConfig.java:64
```

Hoy no vuelca nada porque `logging.level.root: WARN`, pero es un riesgo latente: se activa cambiando una línea de configuración, y volcaría cuerpos completos **y la cabecera `Authorization`** de cada llamada saliente.

Si de verdad hace falta depurar tráfico, que sea condicional y nunca por defecto:

```java
.wiretap(depuracionActivada)       // @Value("${http.client.wiretap:false}")
```

---

## Ficha 17 — SEC-035 y SEC-041 · `assert` para control de flujo y código muerto

**Severidad:** Medium / Low · **Esfuerzo:** 25 min · **Riesgo del cambio:** bajo

**(a) SEC-035.** En `beemailboxes`, `JsonTokenProvider.java:56` y `XmlTokenProvider.java:51`:

```java
assert data != null;                    // <-- inactivo en runtime: la JVM no arranca con -ea
cachedToken = data.getData().getAccessToken();
```

Sustitúyelo por una comprobación real:

```java
if (data == null || data.getData() == null) {
    throw new SantanderException("Respuesta vacia del proveedor de token OTP");
}
cachedToken = data.getData().getAccessToken();
```

Tal como está, si el proveedor devuelve un cuerpo vacío el `assert` no salta y la línea siguiente lanza un `NullPointerException` en mitad del flujo de OTP.

**(b) SEC-041.** Borra `beemailboxes/.../adapters/output/util/UtilsOtp.java`. Está verificado que **nadie lo usa** (el OTP lo genera Celmedia), y contiene un generador de códigos con `ThreadLocalRandom` — no criptográfico — que produce solo números pares de 8 dígitos: la mitad del espacio que aparenta. Si alguien lo reutiliza algún día por su nombre, hereda ese defecto.

---

# Checklist de cierre

Antes de dar el trabajo por terminado:

- [ ] Los 17 cambios aplicados y compilando, con los contratos regenerados.
- [ ] Cada ficha con su **Verificación** ejecutada contra `pre`.
- [ ] **Un test de abuso por hallazgo Critical o High tocado.** No un test unitario: un test que ejecute el caso del atacante y falle si el defecto vuelve. Es lo que faltó en el ciclo anterior y por lo que dos correcciones quedaron a medias.
- [ ] Actualizado el estado en **§20 de `SECURITY_CODE_REVIEW.md`** (`EN REVISIÓN` mientras no exista la prueba de regresión; `CERRADO` cuando exista) y regenerado el Excel con la cadena de scripts documentada en §25.
- [ ] Anotado en el PR qué hallazgo cierra cada cambio, con su ID.

## Lo que quedará abierto después de todo esto

| Hallazgo | Estado tras la guía |
| -------- | ------------------- |
| SEC-002 — BOLA | **Abierto.** Bloqueado por el claim del token (§0) |
| SEC-001 — autenticación en el backend | **Abierto.** Mismo bloqueo |
| SEC-005 — OTP | **Abierto.** Se cierra el código incorrecto; falta el vínculo al usuario y el TTL |
| SEC-058 — volcado documental | **Mitigado, no cerrado.** Depende de SEC-002 |
| SEC-010, SEC-040, SEC-015 | **Abiertos.** Necesitan decisión de producto o del proveedor |
| SEC-019, SEC-021 | **Abiertos.** Necesitan decisión de arquitectura |

**Traducción para el informe del proveedor:** desaparecen unos nueve casos de prueba, pero **API1 (Broken Object Level Authorization) seguirá reportándose**, y en banca esa categoría es la que decide cómo se lee el resto del informe.
