# Desarrollo Seguro: redacción y evidencias por fila

Hoja **"Desarrollo Seguro"** de `2.Controles de seguridad SSDLC y protección de datos_Plantilla.xlsx`.

Este documento no incluye las filas que ya tienen evidencia del arquitecto (9, 10, 12, 13, 14 y 19).

**Cómo usarlo.** En cada fila:

- **K:** valor de "¿Aplica?".
- **L:** responsable.
- **N:** texto para pegar en la columna N. Lo que va entre `[corchetes]` hay que confirmarlo o completarlo antes de pegar.
- **Entregable:** lo que hay que juntar para la columna O.
- **Estado:** si ya lo tienes o a quién pedirlo.

---

## Notas antes de llenar (no van en el Excel)

1. **SAST/SCA (filas 25–28):** en el único log de pipeline que tenemos (KYC, 16/10), el job de análisis no tiene resultado (`analysis_result` vacío). Mientras no llegue el reporte de Fortify SSC, no escribas que "se ejecuta en cada integración".
2. **IriusRisk marca como N/A** el SBOM, la revisión de licencias y el escaneo de dependencias de terceros. Las filas 17, 18 y 48 de este Excel dicen que sí aplican. Si te preguntan, la explicación es esta: el modelo los descartó para los componentes de terceros (BFF, FacePhi, batch de terceros), no para los microservicios propios.
3. **ConfigMap de producción** (`cpe-nxhbsc-k8stecconfmap/config/pro/confimap.yaml`): `CONTACTANOS_BASE_URL` va por **HTTP** a la IP `180.194.16.214`. Esto pega en la fila 22. Conviene aclararlo con Dennis o Jhans antes de afirmar algo.
4. **`GET /hola`** sigue en el API Gateway de producción. Es la primera pregunta que te pueden hacer en la fila 74.
5. **`nube-api-tests` no cuenta como evidencia.** Es un proyecto propio y no está alineado a Santander. El equipo QA no tiene pruebas automatizadas. No lo cites en ninguna fila (pega en la 73).

---

## Definición

### Fila 11 · Risk assessment preliminar

- **K:** Sí. **L:** eCISO (Keivein Martinez).
- **N:**
  > Ciberseguridad ejecutó la evaluación de riesgos preliminar (CYRA) entre el 30/03/2026 y el 17/04/2026. Al ser una iniciativa nivel A, la realizó el eCISO.
- **Entregable:** informe de la CYRA preliminar y el Anexo 3 lleno.
- **Estado:** pedir a **Keivein Martinez**.

---

## Diseño

### Fila 15 · Controles de seguridad funcionales

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Las historias de usuario incluyen controles de seguridad funcionales:
  > - OTP con vigencia y número de intentos limitado en el envío de correo.
  > - Validación biométrica (prueba de vida y validación facial contra RENIEC) antes de la firma.
  > - Validación de entrada en cada endpoint según su contrato OpenAPI.
  > - Límite de peticiones por consumidor en el API Gateway.
  > - Consentimiento de tratamiento de datos antes de procesar información del cliente.
  >
  > Se registran en el tracker de requerimientos del proyecto.
- **Entregable:** lista de controles funcionales por historia o requerimiento.
- **Estado:** **lo armas tú** a partir de `nube-docs/docs/REQUIREMENTS_AND_DEBT_TRACKER.md`, `03_apis/catalogos/Ratelimits - Gateway.xlsx` y las guías de consumo.

### Fila 16 · Límites de confianza y flujo de datos

- **K:** Sí. **L:** DES.
- **N:**
  > El flujo de datos se documenta con cinco límites de confianza:
  > 1. **Internet:** app y BFF de Conexa.
  > 2. **Borde:** Imperva y AWS WAF.
  > 3. **Entrada a AWS:** API Gateway, con autenticación en Cognito y Lambda Authorizer.
  > 4. **Red privada:** PrivateLink y NLB hacia los microservicios en subred privada de EKS.
  > 5. **Salidas:**
  >    - a proveedores por Firewall Norte y Cisco Umbrella;
  >    - a sistemas internos por Firewall Sur y GSNET;
  >    - a los datos (DynamoDB, RDS, S3) en la cuenta WL.
  >
  > La justificación de cada límite está en el ADR-001.
- **Entregable:** diagrama de flujo de datos con los límites marcados, más el ADR-001.
- **Estado:** el ADR lo tienes (`06_seguridad/ADR-001-Seguridad-de-las-APIs-de-integracion.md`). El diagrama **lo armas tú**: sobre el diagrama de la fila 10, dibuja las cinco fronteras y numera los flujos.

### Fila 17 · Escaneo de librerías

- **K:** Sí. **L:** DES.
- **N:**
  > Las librerías se descargan solo del repositorio corporativo Nexus. El análisis de componentes (SCA) de Fortify está habilitado en el pipeline de Gluon de cada componente.
- **Entregable:** informe SCA de Fortify SSC por componente.
- **Estado:** pedir a **Jorge Flores** (hizo la solicitud SCA por ServiceNow) o a **Keivein Martinez**.

### Fila 18 · Librerías sin vulnerabilidades conocidas

- **K:** Sí. **L:** DES.
- **N:**
  > Las vulnerabilidades encontradas en dependencias se corrigen subiendo la versión de la librería en el `pom.xml` de cada componente. Las versiones corregidas quedan fijadas para que no regresen con una actualización del parent.
- **Entregable:** informe de remediación (SCA antes y después) o el detalle de las CVE corregidas por componente.
- **Estado:** parcial. Las versiones fijadas por CVE están en los `pom.xml`. El informe formal hay que pedirlo junto con el de la fila 17.

### Fila 20 · Inventario y clasificación de datos

- **K:** Sí. **L:** DES.
- **N:**
  > El inventario de datos indica para cada dato:
  > - dónde se almacena (DynamoDB, S3, RDS);
  > - qué componente lo usa;
  > - su clasificación y su propietario;
  > - los controles que aplican: cifrado con KMS, acceso por rol IRSA y retención.
- **Entregable:** `Nube_Inventario_Data_v2.xlsx` e `Inventario_DynamoDB_por_componente.md`.
- **Estado:** tienes las dos cosas (`04_modulos/proveedores/` y `04_modulos/lambda-autorizer-corporativo/`). Falta completar la hoja de proveedores y el cifrado de RDS: pedir a **Jhans De La Cruz**.

### Fila 21 · Logs de seguridad hacia el SIEM

- **K:** Sí. **L:** DES.
- **N:**
  > Generan logs de seguridad:
  > - Imperva y AWS WAF: bloqueos;
  > - Cognito y API Gateway: autenticación y acceso;
  > - CloudTrail: acciones sobre la cuenta;
  > - los microservicios: CloudWatch y Dynatrace, con retención mayor a un año.
  >
  > [Indicar el colector y cómo llegan al SIEM Global.]
- **Entregable:** documento con la lista de fuentes de log, el colector y el destino SIEM.
- **Estado:** pedir a **Jhans De La Cruz**. Es la misma duda abierta del Index 32 del risk assessment.

### Fila 22 · Modelo criptográfico

- **K:** Sí. **L:** DES.
- **N:**
  > - **En tránsito:** TLS en la exposición pública, con el certificado gestionado en ACM. Dentro de AWS, PrivateLink.
  > - **En reposo:** DynamoDB y S3 se cifran con AWS KMS [tipo de llave: AWS managed / customer managed].
  > - **Secretos:** las credenciales de proveedores se guardan en AWS Secrets Manager.
  > - **Tokens:** el token interno lo firma el Lambda Authorizer corporativo.
- **Entregable:** documento del modelo criptográfico y captura de la llave KMS por recurso.
- **Estado:**
  - El tipo de llave KMS y la captura de Secrets Manager: pedir a **Jhans**.
  - El documento **lo armas tú** con esos datos.

### Fila 23 · Arquitectura de red

- **K:** Sí. **L:** DES.
- **N:**
  > La arquitectura de red separa:
  > - **perímetro a internet:** Imperva y AWS WAF;
  > - **cuenta EKS:** API Gateway, PrivateLink y subred privada;
  > - **cuentas de Networking** local y global, con Transit Gateway;
  > - **salida a internet:** Firewall Norte con Cisco Umbrella;
  > - **conexión a GSNET:** Firewall Sur;
  > - **cuenta WL** de datos.
- **Entregable:** diagrama de red.
- **Estado:** tienes `02_arquitectura/aws-infra/Arquitectura_PREPROD_Nube.png`, que es el mismo de la fila 10. Sirve tal cual.

---

## Construcción

### Fila 25 · SAST

- **K:** Sí. **L:** DEV (Jorge Flores).
- **N:**
  > El análisis estático lo ejecuta Fortify (ScanCentral y SSC) en el pipeline de integración de Gluon de cada componente. En `.gluon/ci/ci.yml` están habilitados SAST, SCA, calidad de código y escaneo de imagen.
- **Entregable:** informe Fortify SSC por componente, con fecha y resumen por severidad.
- **Estado:** pedir a **Jorge Flores** o a **Keivein Martinez**. Ver la nota 1.

### Fila 26 · SCA

- **K:** Sí. **L:** DEV.
- **N:**
  > El análisis de componentes de terceros lo ejecuta Fortify en el mismo pipeline de Gluon, con la política corporativa `GLUON_3RDParties_CS-ST009`.
- **Entregable:** informe SCA (es el mismo de la fila 17).
- **Estado:** pedir a **Jorge Flores**.

### Fila 27 · Revisión de hallazgos SAST/SCA

- **K:** Sí. **L:** DEV y Ciberseguridad.
- **N:**
  > Ciberseguridad revisó los informes SAST y SCA del último pull request (abril de 2026). Además, se hizo una revisión de código seguro de los componentes, con hallazgos clasificados por severidad y su plan de remediación.
- **Entregable:** plan de remediación.
- **Estado:**
  - Tienes `06_seguridad/security-code-review/SECURITY_CODE_REVIEW_EJECUTIVO_v2.6.xlsx` y los `REMEDIACION_*.md`.
  - Pedir a **Keivein** la revisión de Fortify.

### Fila 28 · Seguimiento de la remediación

- **K:** Sí. **L:** DEV.
- **N:**
  > La remediación se sigue por versión. Cada nueva revisión se compara con la anterior para confirmar qué hallazgos se cerraron.
- **Entregable:** evidencia de la ejecución del plan.
- **Estado:** tienes las comparativas (`comparativa-v*.md`) y la hoja de remediación del Excel ejecutivo.

### Fila 29 · Protección de repositorios (fila madre)

- **K:** Sí. **L:** DEV.
- **N:**
  > El código está en el GitHub corporativo del banco y lo gestiona la plataforma Gluon. Varios de estos controles los aplica la plataforma para todos los repositorios. Se adjunta el checklist con la evidencia de cada punto.
- **Entregable:** checklist de las filas 30 a 39 lleno, con capturas.
- **Estado:** lo armas tú con lo que te den Jhans y plataforma.

| Fila | Texto para N | Evidencia | ¿De dónde sale? |
|---|---|---|---|
| 30 Inventario de repos | Los repositorios del proyecto están inventariados, son privados y cada uno tiene owner asignado (ver anexo A). | Anexo A de este documento y captura de visibilidad | Tú. Owner: confirmar con **Dennis** |
| 31 Integración con Entra ID | El acceso al GitHub corporativo se hace con la cuenta corporativa, por SSO con Entra ID. | Captura del login SSO o de la organización | **Jhans** o plataforma Gluon |
| 32 Menor privilegio | Solo el equipo del proyecto tiene acceso a los repositorios. Los desarrolladores no pueden desplegar en UAT ni en producción. | Captura de *Settings → Collaborators and teams* (E-37.1) | Tienes la captura del risk assessment |
| 33 Revisión periódica de accesos | Los accesos se revisan [frecuencia] y se retiran los de personas que dejan el proyecto. | Registro de la última revisión | **Dennis** o **Marco Risco**. Si no existe, marcar "No cumple" y definir la frecuencia |
| 34 MFA | El acceso exige MFA, que aplica Entra ID a las cuentas corporativas. | Captura de la política de MFA | **Jhans** o plataforma |
| 35 Escaneo de secretos | [Indicar si GitHub secret scanning o Gluon revisa secretos en cada push.] | Captura de la configuración o de un reporte | Plataforma Gluon |
| 36 *Break the build* | El pipeline tiene un *security gate* de Fortify que corta la ejecución con hallazgos de severidad alta o mayor. | Log del paso "SSDLC Security Gate" | Tienes el log DAST (`risk-assessment/logs-pipeline/`). Pedir uno de SAST a **Jorge** |
| 37 Firma y cifrado del código | [Confirmar si Gluon firma las imágenes o los artefactos que publica en JFrog.] | Captura o documentación de la plataforma | Plataforma Gluon |
| 38 Rotación de secretos del CI/CD | Los secretos del pipeline los administra Gluon y se heredan a cada repositorio (`secrets: inherit`). [Indicar la política de rotación.] | Política de rotación | **Jhans** o plataforma |
| 39 Protección de ramas | Los cambios a `main`, `release/**` y `hotfix/**` entran por pull request con aprobación. | Captura de las reglas de protección de ramas | **Jhans** o el admin del repo |

### Fila 40 · Datos reales en entornos no productivos

- **K:** Sí. **L:** DEV.
- **N:**
  > En los entornos previos se usan los datos de prueba de cada proveedor. No se usan datos de clientes. Cuando una validación necesita datos reales (por ejemplo, la validación facial contra RENIEC), se usan los de miembros del equipo, con su consentimiento y solo en UAT. UAT tiene los mismos controles que producción.
- **Entregable:** informe de la técnica usada para los datos en entornos previos.
- **Estado:**
  - **Lo redactas tú** con este texto.
  - Adjunta el consentimiento del equipo si existe: pedir a **Marco Risco**.
  - Revisa antes la traza con datos en claro de Contáctanos en PRE (duda D-05).

### Fila 41 · Seguridad del CI/CD (fila madre)

- **K:** Sí. **L:** DEV.
- **N:**
  > La integración y el despliegue usan los workflows reutilizables corporativos de Gluon (`sgt-glna360-reuscommonswfs`). Se adjunta el checklist con la evidencia de cada punto.
- **Entregable:** checklist de las filas 42 a 47.
- **Estado:** lo armas tú.

| Fila | Texto para N | Evidencia | ¿De dónde sale? |
|---|---|---|---|
| 42 Canales cifrados | La entrega usa HTTPS entre GitHub, el registro de imágenes de Gluon (JFrog) y el clúster EKS. | Log del pipeline de despliegue | Tienes `log pipeline - kyc.zip` |
| 43 Mínimo privilegio y separación de roles | El despliegue solo se puede hacer desde el pipeline, y los desarrolladores no tienen permisos en UAT ni en producción. El paso a producción pide el número de tarea de ServiceNow. | `cd.yml` (campo *SNOW Task Number*) y captura de permisos | Tienes el `cd.yml` de cualquier repo |
| 44 Supervisión de despliegues a producción | Cada despliegue a producción queda registrado en el pipeline y se asocia a una tarea de ServiceNow aprobada. | Ejecución de un despliegue a producción con su tarea | **Jhans** |
| 45 Credenciales mínimas por pipeline | Cada componente usa su propio rol (IRSA) y solo accede a sus recursos AWS. | Política IAM de un rol IRSA | **Jhans** |
| 46 Despliegue desde ramas confiables | La integración se dispara solo desde `development`, `main`, `release/**` y `hotfix/**`. Producción se despliega desde una versión liberada. | `integration.yml` y `release.yml` | Tienes los workflows en cada repo |
| 47 Gestión de credenciales del pipeline | Las credenciales del pipeline se guardan como secretos de la plataforma, no en el código. [Indicar el procedimiento de rotación.] | Procedimiento de rotación | **Jhans** o plataforma |

### Fila 48 · SBOM

- **K:** Sí. **L:** DEV.
- **N:**
  > Se validó la lista de componentes de terceros (SBOM) de cada microservicio, con versión y licencia.
- **Entregable:** el SBOM.
- **Estado:** pedir a **Jorge Flores**, que hizo la validación del SBOM entre el 27/04 y el 30/04. Si no aparece, se genera con CycloneDX desde Maven.

---

## Adquisición (proveedores externos)

**Alcance:** se evalúan los servicios integradores (los microservicios) y los proveedores SaaS que consumen. Los cuatro son de caja negra:

- FacePhi (biometría y firma);
- Celmedia (correo y OTP), con Acoustic como plataforma detrás;
- Gesintel (listas de riesgo);
- GDS Modellica (riesgo).

**Conexa** (app, BFF y el SDK de FacePhi que va dentro de la app) **queda fuera del alcance** de esta sección.

Como son caja negra, no se puede revisar su proceso por dentro. La evidencia son certificaciones de terceros, documentos del proveedor y cláusulas del contrato. Si un proveedor no entrega, se le nombra en N y la fila queda *En validación*.

### Fila 51 · SSDLC del proveedor

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Los servicios integradores consumen a FacePhi, GDS Modellica, Celmedia y Gesintel como SaaS (caja negra). Su SSDLC se valida con certificaciones de terceros: [ISO 27001 / SOC 2 por proveedor].
- **Entregable:** certificación o atestación de cada proveedor (ISO 27001, SOC 2), o una carta sobre su SSDLC.
- **Estado:** pedir a **Dennis Aviles** o a Compras; debería estar en la homologación de terceros (nov 2025 a ene 2026).

### Fila 52 · Identificación de vulnerabilidades del proveedor

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Cada proveedor gestiona las vulnerabilidades de su servicio y debe notificar al banco según [contrato o anexo de seguridad]. [Indicar los proveedores que entregaron su política.]
- **Entregable:** política de vulnerabilidades de cada proveedor y la cláusula que lo obliga a avisar al banco.
- **Estado:** pedir a **Dennis** o a Compras.

### Fila 53 · Programa de respuesta a vulnerabilidades

- **K:** Sí. **L:** T&O PM.
- **N:**
  > [Por proveedor: indicar si tiene un programa formal y si hace pentest periódico de su servicio.]
- **Entregable:** carta o informe del proveedor (resumen de su último pentest, si lo comparte).
- **Estado:** pedir a cada proveedor.

### Fila 54 · El programa cubre el hardening

- **K:** No.
- **N:**
  > No aplica. Los proveedores son SaaS y dan servicio por API desde su nube. No hay appliances ni software suyo en el banco. El hardening de su infraestructura es responsabilidad de cada proveedor.
- **Entregable:** ninguno.

### Fila 55 · Parches y actualizaciones controladas

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Los parches del servicio SaaS los aplica el proveedor sin cambiar el contrato de la API, y avisa los cambios según [contrato]. Del lado del banco, la URL y la versión de cada proveedor están en el ConfigMap y solo cambian por el pipeline de despliegue.
- **Entregable:** cláusula o documentación de versionado y aviso de cambios del proveedor, más el ConfigMap (`cpe-nxhbsc-k8stecconfmap`) con las URLs de los proveedores.
- **Estado:** la parte del proveedor, pedir a **Dennis** o a Compras. El ConfigMap lo tienes.

### Fila 56 · Inventario de componentes del proveedor

- **K:** No.
- **N:**
  > No aplica. Los proveedores se consumen como SaaS por API y no instalan componentes en la infraestructura del banco.
- **Entregable:** ninguno.

### Fila 58 · Evaluación de riesgos del proveedor

- **K:** Sí. **L:** eCISO.
- **N:**
  > Los proveedores están clasificados como terceros críticos. Cada uno pasó por la evaluación de riesgos de terceros de Ciberseguridad.
- **Entregable:** evaluación de riesgo de cada proveedor.
- **Estado:** pedir a **Keivein Martinez**.

### Fila 59 · Controles compensatorios aprobados por el CISO

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Donde un control no se pudo implementar, se presentó un waiver con su control compensatorio. Es el caso del consumo del API de Contáctanos en UAT, revisado por Ciberseguridad y Riesgos No Financieros.
- **Entregable:** presentación del waiver y la aprobación del CISO local.
- **Estado:**
  - Tienes el waiver: `06_seguridad/waivers/contactanos/Waiver_reclamos_v1.3.pptx`.
  - Falta el correo o acta de aprobación de **Claudia Vasquez**.

### Filas 60 a 63 · Manuales, hardening y análisis de brechas

- **K:** No.
- **N** (el mismo texto para las cuatro):
  > No aplica. Los proveedores se consumen como servicio por API y no se instala software suyo en la infraestructura del banco. El hardening de la infraestructura propia (EKS e imágenes) se revisa en el checklist del Anexo 7 (fila 67).
- **Entregable:** ninguno.

### Fila 64 · URLs, IPs y puertos de los proveedores

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Se identificaron las URLs y los puertos de cada proveedor (ver la matriz de conectividad) y se registraron en la lista blanca del proxy corporativo. La salida a internet pasa por Cisco Umbrella.
- **Entregable:** matriz de conectividad.
- **Estado:**
  - Tienes una base en el anexo B de este documento y en `04_modulos/contactanos-reclamos/Plantilla Regla firewall - Proyecto Nube.xlsx`.
  - Pedir a **Keivein** las IPs mapeadas (DEV y UAT) y el ticket de lista blanca.

### Fila 65 · Definición de reglas de firewall

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Las reglas se pidieron por ticket para cada ambiente: ACL de Santander y de Conexa, lista blanca y reglas de firewall de UAT.
- **Entregable:** tickets de solicitud.
- **Estado:** pedir a **Keivein** (UAT) y a **Dennis** (ACL de producción).

### Fila 66 · Configuración de firewalls

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Las reglas se configuraron y se probaron con pruebas internas y externas en UAT (junio de 2026). [Producción: indicar el estado.]
- **Entregable:** ticket atendido y resultado de las pruebas de firewall.
- **Estado:** pedir a **Dennis Aviles**.

### Fila 67 · Anexo 7 (checklist antes de producción)

- **K:** Sí. **L:** T&O PM.
- **N:**
  > Se revisó el checklist del Anexo 7 antes del pase a producción. Se adjunta con la evidencia de cada punto.
- **Entregable:** el Anexo 7 lleno.
- **Estado:** lo armas tú. Por punto:
  - hardening, Qualys y CrowdStrike en nodos EKS: **Jhans**;
  - WAF y Anti-DoS: **Keivein** (Imperva y Akamai);
  - CMDB/APM: **Dennis**;
  - SOC: **Jhans**;
  - vulnerabilidades: las filas 25 a 28 y 70 a 72.

---

## Testing

### Fila 68 · SAST, si no se hizo en construcción

- **K:** No, si la fila 25 tiene el reporte. Sí, si no lo tiene.
- **N:**
  > Se cubre en la fase de construcción (fila 25).
- **Entregable:** el mismo de la fila 25.

### Fila 69 · SCA, si no se hizo en construcción

- **K:** igual que la fila 68.
- **N:**
  > Se cubre en la fase de construcción (fila 26).
- **Entregable:** el mismo de la fila 26.

### Fila 70 · DAST

- **K:** Sí. **L:** TES.
- **N:**
  > El análisis dinámico se ejecuta con Fortify WebInspect en un pipeline aparte del despliegue. Los resultados se publican en Fortify SSC. Último escaneo: [fecha y alcance].
- **Entregable:** informe DAST.
- **Estado:**
  - Tienes 5 reportes en `06_seguridad/dast/` y el log del pipeline.
  - El último escaneo cubrió una sola ruta en DEV. Pedir a **Keivein** el informe de SSC con todas las rutas en UAT.

### Fila 71 · Corrección de hallazgos DAST

- **K:** Sí. **L:** TES (en el Excel L está vacía: llenarla).
- **M:** *En validación* hasta tener el re-escaneo. No hay waiver: los 4 altos tienen que estar corregidos antes del pase.
- **N:**
  > El DAST no reportó vulnerabilidades críticas. Los 4 altos de cifrado SSL débil en DEV se corrigieron con el ajuste de cifrados del dominio [ticket de Infra] y el re-escaneo del [fecha] no los reporta.
- **Entregable:** ticket de Infra y re-escaneo DAST (o prueba de cifrados del dominio) sin los 4 altos.
- **Estado:** pedir el ticket y el re-escaneo a **Infra** o a **Keivein**. E-25.4 (TLS 1.2) sirve de apoyo, no reemplaza el re-escaneo.

### Fila 72 · Ethical hacking

- **K:** Sí. **L:** TES.
- **N:**
  > Al ser un activo expuesto a internet, se ejecutó ethical hacking con Deloitte en UAT. La aplicación móvil se probó con enfoque de caja gris entre el 23/09/2026 y el 01/10/2026. [Indicar el EH de las APIs de integración, el retest y la conformidad del CISO.]
- **Entregable:** informe de EH, informe de retest y conformidad del CISO.
- **Estado:**
  - Tienes `security-code-review/EH Personalizado - LAB - Proyecto Nube - 20260830 (1).xlsx`.
  - El informe de Deloitte, el retest y la conformidad: pedir a **Keivein** y **Claudia Vasquez**.

### Fila 73 · Regresión de seguridad automatizada

- **K:** Sí. El control aplica porque el activo está expuesto a internet; no marcar "No aplica". **L:** TES.
- **M:** *En proceso*. Si la lista del Excel tiene "No cumple", úsala, pero siempre con el plan de acción. No poner "Finalizado" ni "En validación".
- **N:**
  > No existe una suite automatizada de regresión de seguridad; el equipo QA ejecuta pruebas funcionales manuales. Como cobertura actual, en cada build el pipeline de Gluon ejecuta SAST, SCA y escaneo de imagen con corte del despliegue (filas 25, 26 y 36), y el DAST con Fortify WebInspect se puede volver a ejecutar desde su pipeline (fila 70). Las vulnerabilidades corregidas del ethical hacking se validaron con retest (IDOR certificado el 23/10/2026). Plan: [definir casos de regresión de seguridad (sin token, token inválido, entradas fuera de contrato, límite de OTP) y ejecutar el DAST antes de cada pase a producción. Responsable: ___. Fecha: ___].
- **Entregable:** las referencias a las filas 25, 26, 36 y 70 y a E-76.1 (retest del IDOR), más el plan de acción con su responsable y fecha. No hace falta una captura nueva.
- **Estado:**
  - **No usar `nube-api-tests`** (ver la nota 5).
  - El responsable y la fecha del plan los pone QA o el PM (**Marco Risco** o **Diego**), no desarrollo. Si nadie se compromete, presentar "No cumple" con un waiver, como se hizo en la fila 59.
  - Preguntar a QA si sus casos manuales incluyen alguno de seguridad (por ejemplo, el bloqueo de OTP). Si los incluyen, agregar a N: "QA valida manualmente en cada regresión: ___".

| Control que se acerca | ¿Automático? | Evidencia |
|---|---|---|
| SAST, SCA y escaneo de imagen en el pipeline de Gluon (cortan el despliegue) | Sí, en cada build | Filas 25, 26 y 36 |
| DAST con Fortify WebInspect | Sí, se dispara a pedido | Fila 70 (E-70.x) |
| Retest del ethical hacking (IDOR certificado el 23/10/2026) | No, manual | E-76.1 |
| Pruebas funcionales de QA | No, manuales | Confirmar si incluyen casos de seguridad |

---

## Despliegue

### Fila 74 · Quitar herramientas y accesos de DEV/UAT

- **K:** Sí. **L:** DEV.
- **N:**
  > La configuración de producción es propia de ese ambiente:
  > - se quitaron del API Gateway el retorno de firma y su autorizador, que solo existen en UAT;
  > - la traza de datos en claro de Contáctanos está apagada.
  >
  > [Indicar qué pasa con `GET /hola`.]
- **Entregable:** export del API Gateway de producción y ConfigMap de producción.
- **Estado:**
  - Tienes `03_apis/apigateway/prod/PROD_nexhub-api-ifa-oas30-apigateway.json` y el ConfigMap en el repo `cpe-nxhbsc-k8stecconfmap`.
  - Revisa antes la nota 4.

### Fila 75 · Risk assessment final

- **K:** Sí. **L:** eCISO.
- **N:**
  > Ciberseguridad ejecutó la evaluación de riesgos final (CYRA) antes del pase a producción, actualizando la preliminar con los resultados de las pruebas de seguridad.
- **Entregable:** informe de la CYRA final.
- **Estado:** pedir a **Keivein**. Tu borrador de respuestas está en `risk-assessment/Risk_Assessment_Respuestas.md`.

### Fila 76 · Tratar riesgos y vulnerabilidades críticas y altas

- **K:** Sí. **L:** T&O PM.
- **M:** *Finalizado* solo si todos los altos están corregidos y validados antes del pase; si alguno sigue abierto, *En validación*. **No hay waiver para este caso.**
- **N:**
  > No hubo vulnerabilidades críticas. Los altos se corrigieron antes del despliegue: el IDOR del EH, certificado el 23/10/2026; el alto de la app, corregido por Conexa y validado en el retest del [fecha]; y los 4 altos de cifrado SSL del DAST, corregidos por Infra (fila 71). [SCA: pendiente del informe de Fortify.]
- **Entregable:** consolidado de críticos y altos por fuente, con su evidencia de cierre.

| Fuente | Críticos / altos | Tratamiento | Evidencia |
|---|---|---|---|
| SAST | 0 / 0 | No aplica | Fila 25 |
| SCA | Sin informe | Si trae altos, también deben corregirse | Pendiente de **Jorge Flores** |
| DAST | 0 / 4 (SSL en DEV) | Ajuste de cifrados por Infra | Fila 71 (ticket y re-escaneo) |
| EH Deloitte | 0 / 2 | IDOR corregido y certificado; alto de la app corregido por Conexa | E-76.1, retest de Conexa |

- **Estado:**
  - Retest del alto de Conexa: pedir a **Keivein** o a **Conexa**.
  - Re-escaneo SSL: fila 71.
  - Usar la versión del EH de 16 hallazgos (2 altos), no la de 14.

---

## Pedidos por persona

| Persona | Qué pedir | Filas |
|---|---|---|
| **Keivein Martinez** (Ciberseguridad) | CYRA preliminar y final, revisión Fortify, IPs mapeadas, ticket de lista blanca, tickets de firewall y ACL de UAT, DAST completo, informe de Deloitte y retest (incluido el del alto de Conexa), re-escaneo DAST de los altos SSL, evaluación de riesgo de proveedores | 11, 27, 58, 64, 65, 70–72, 75, 76 |
| **Claudia Vasquez** (CISO local) | Aprobación de los waivers y conformidad del EH | 59, 72 |
| **Jorge Flores** | Informes SAST y SCA de Fortify SSC, SBOM, log del *security gate* de SAST | 17, 18, 25, 26, 36, 48, 76 |
| **Jhans De La Cruz** (DevOps) | SIEM y logs, tipo de llave KMS, cifrado de RDS, Secrets Manager, Entra ID y MFA, rotación de secretos, protección de ramas, rol IRSA, despliegue a producción con tarea SNOW, hardening, Qualys y CrowdStrike | 20–22, 31, 34, 38, 39, 44, 45, 47, 67 |
| **Dennis Aviles** (Arquitectura) o Compras | Owner de cada repo; de cada proveedor SaaS: certificaciones, política de vulnerabilidades, cláusulas de aviso y versionado; ACL y firewall de producción; ficha CMDB/APM | 30, 51–53, 55, 65–67 |
| **Plataforma Gluon** | Escaneo de secretos, firma de artefactos, política de rotación | 35, 37, 38 |
| **Marco Risco** | Revisión periódica de accesos, consentimiento del equipo para usar sus datos en UAT, responsable y fecha del plan de regresión de seguridad, casos manuales de QA | 33, 40, 73 |
| **Lo armas tú** | Controles funcionales, diagrama de flujo de datos, modelo criptográfico, checklists de repos y CI/CD, informe de datos de prueba, texto de la fila 73 (sin `nube-api-tests`), Anexo 7 | 15, 16, 22, 29, 40, 41, 67, 73 |

---

## Anexo A · Inventario de repositorios (fila 30)

| Repositorio | Tipo | Visibilidad | Owner |
|---|---|---|---|
| cpe-nxhbsc-beclaims | Microservicio: libro de reclamaciones | Privado | [ ] |
| cpe-nxhbsc-becreditrisk | Microservicio: riesgo crediticio | Privado | [ ] |
| cpe-nxhbsc-bedatacomanagment | Microservicio: consentimiento de datos | Privado | [ ] |
| cpe-nxhbsc-bedigitsignature | Microservicio: firma digital | Privado | [ ] |
| cpe-nxhbsc-bedocmanagement | Microservicio: gestión documental | Privado | [ ] |
| cpe-nxhbsc-beemailboxes | Microservicio: correo y OTP | Privado | [ ] |
| cpe-nxhbsc-beemailsend | Microservicio: correo y OTP | Privado | [ ] |
| cpe-nxhbsc-beidentbiometric | Microservicio: validación biométrica | Privado | [ ] |
| cpe-nxhbsc-beknowyocustomer | Microservicio: KYC | Privado | [ ] |
| cpe-nxhbsc-beproducoffering | Microservicio: oferta de productos | Privado | [ ] |
| cpe-nxhbsc-bewatchscreening | Microservicio: listas de riesgo | Privado | [ ] |
| cpe-nxhbsc-lmauthorizer | Lambda Authorizer (retorno de firma) | Privado | [ ] |
| cpe-nxhbsc-k8stecconfmap | Configuración: namespace técnico | Privado | [ ] |
| cpe-nxhbsc-k8snegconfmap | Configuración: namespace de negocio | Privado | [ ] |
| cpe-nxhbsc-cdappcomponent | Configuración de aplicación y pipeline DAST | Privado | [ ] |

Visibilidad y owner hay que confirmarlos en el GitHub corporativo.

## Anexo B · Destinos externos para la matriz de conectividad (fila 64)

Sacado del ConfigMap de producción. Todo es HTTPS por el puerto 443, salvo donde se indica.

| Proveedor | Host | Uso |
|---|---|---|
| FacePhi | `api.identity-platform.io` | Biometría y firma |
| Celmedia | `otpsantander.celmediamobile.pe` | OTP y correo |
| Acoustic (detrás de Celmedia) | `api-campaign-us-2.goacoustic.com`, `transact-campaign-us-2.goacoustic.com` | Envío de correo |
| Gesintel | `api.amlupdate.com` | Listas de riesgo |
| GDS Modellica | `creditcards.sca-mt.prod.me.dataview360.com` | Riesgo crediticio |
| Contáctanos (interno, GSNET) | `180.194.16.214` ⚠️ HTTP, puerto 80 | Reclamos |
| Santander | `api.santanderconsumer.com.pe` | API corporativa |
