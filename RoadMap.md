# Roadmap: Despliegue Distribuido del Esquema HBS Threshold

## Contexto y punto de partida

El paper implementa un esquema de firma threshold sobre LMS donde un **Dealer** de confianza realiza el setup, un **Aggregator** no confiable coordina las rondas de firma, y un conjunto de **Trustees** mantienen cada uno únicamente su clave PRF secreta `K[t]` y su lista de KeyIDs disponibles. El CRV (Common Reference Value) es el artefacto público central: por cada KeyID contiene los campos `R`, `CHK`, `PATH` y `SK` cifrados por XOR contra los shares PRF de cada trustee. Su tamaño es del orden de **9 KiB por KeyID** para parámetros típicos de Winternitz.

El objetivo es pasar de la simulación en memoria actual a un sistema distribuido real donde cada rol vive en un contenedor Docker independiente, los trustees y el aggregator se comunican mediante una API de red, y el CRV junto con la coalition list (CL) se almacenan en un **Content Addressable Storage (CAS)** en lugar del `PublicBulletinBoard` en memoria.

---

## Fase 0 — Prerequisitos y decisiones de arquitectura

Antes de escribir una sola línea de código de red, hay que fijar tres decisiones que afectan a todo lo demás.

### 0.1 Protocolo de comunicación: gRPC

El paper especifica que la comunicación va del aggregator a cada trustee individualmente (punto a punto, sin broadcast). Los mensajes son exclusivamente arrays de bytes: `Round1Msg` contiene `R_t` y `CHK_t`; `Round2Msg` contiene `Z_t` y `PATH_t`. Esto encaja perfectamente con **gRPC + Protocol Buffers**: serialización binaria nativa, sin Base64, tipado fuerte, y generación automática de stubs en Java.

```protobuf
// trustee.proto
service TrusteeService {
  rpc ShardSign1 (Sign1Request) returns (Sign1Response);
  rpc ShardSign2 (Sign2Request) returns (Sign2Response);
}

message Sign1Request {
  bytes key_id  = 1;
  bytes message = 2;
  int32 n       = 3;
  int32 length_chk = 4;
}

message Sign1Response {
  bytes r_t   = 1;
  bytes chk_t = 2;
  bool  abort = 3; // true si el trustee devuelve ⊥
}
```

El Dealer también necesita un servicio para distribuir claves PRF a cada trustee en setup, aunque esto sólo ocurre una vez.

### 0.2 CAS: implementación propia minimalista

El CRV para un esquema con D=1024 KeyIDs ocupa aproximadamente **9 MiB**. El CAS sólo necesita dos operaciones: `PUT(blob) → CID` y `GET(CID) → blob`, donde el CID es el SHA-256 del contenido. Una implementación propia en Java (un servidor HTTP sencillo con Spring Boot o Javalin) es más controlable que IPFS para un prototipo y permite verificar integridad de forma trivial. La extensión a IPFS en el futuro es directa porque la semántica es idéntica.

La ventaja criptográfica del CAS es relevante para el modelo de amenaza del paper: el aggregator puede verificar que el CRV no ha sido alterado comparando el CID que obtuvo del Dealer con el hash del blob descargado, sin necesidad de ningún canal adicional de autenticidad.

### 0.3 Persistencia del estado del Trustee

El trustee tiene estado crítico entre Round1 y Round2: la variable `current` (el mensaje en curso) y el campo `keyID`. Si el contenedor se reinicia entre las dos rondas, el trustee queda en estado incoherente. Se necesita persistencia mínima: **SQLite embebido** es suficiente para un prototipo. El esquema tiene dos tablas:

```sql
-- Claves PRF y lista de KeyIDs disponibles (se inicializa en setup)
CREATE TABLE keylist (key_id INTEGER PRIMARY KEY);

-- Estado entre Round1 y Round2
CREATE TABLE signing_state (
    key_id   BLOB NOT NULL,
    message  BLOB NOT NULL,
    created  INTEGER NOT NULL  -- timestamp Unix, para expiración
);
```

---

## Fase 1 — Refactoring previo: separar interfaces de implementaciones

Antes de dockerizar, el código Java necesita un refactoring que separe la lógica criptográfica (que no cambia) de cómo se accede al estado y al CRV. Esto es imprescindible para que los tests de integración funcionen correctamente.

### 1.1 Extraer interfaz `CRVStore`

Actualmente `PublicBulletinBoard` almacena el CRV en memoria como un array. Se define una interfaz:

```java
public interface CRVStore {
    String put(int keyID, CRV crv);     // devuelve CID
    CRV    get(String cid);
    String putCL(int[][] cl);
    int[][] getCL(String cid);
}
```

Con dos implementaciones: `InMemoryCRVStore` (para tests unitarios, comportamiento actual) y `HttpCASCRVStore` (para el despliegue real, delega en el servidor CAS).

### 1.2 Extraer interfaz `TrusteeStateStore`

```java
public interface TrusteeStateStore {
    boolean    claimKeyID(int keyID);           // atómico: devuelve false si ya usado
    void       saveSigningState(byte[] keyID, byte[] message);
    SigningState loadAndClearSigningState();     // lee y borra en una transacción
    void       addKeyID(int keyID);
}
```

Con implementaciones `InMemoryTrusteeStateStore` (comportamiento actual de los campos `keyID`, `current`, `usedKeyIDs`, `keyList`) y `SQLiteTrusteeStateStore`.

El hecho de que `claimKeyID` sea atómico es importante: en el paper, el trustee debe detectar si el aggregator intenta reutilizar un KeyID (el "Disjoint Honest Trustees Problem" de la sección 4.1). SQLite garantiza atomicidad con una simple transacción.

### 1.3 Tests de integración antes de dockerizar

Con las interfaces extraídas, se pueden escribir tests de integración que prueben el protocolo completo usando las implementaciones reales (SQLite + CAS HTTP) contra servicios locales. Esto es mucho más fácil de depurar que hacerlo directamente en Docker.

---

## Fase 2 — Servidor CAS

Un servidor HTTP sencillo con dos endpoints:

```
POST /blobs          body: bytes → 201 Created, Location: /blobs/{sha256hex}
GET  /blobs/{cid}   → 200 OK, body: bytes
```

La implementación en Java con Javalin o Spring Boot es de unas 50 líneas. El almacenamiento puede ser el sistema de ficheros local (un fichero por CID en un directorio configurable).

El Dealer, tras ejecutar `ShardSetup`, llama al CAS para publicar:
- El array completo de CRVs serializado → obtiene `CRV_CID`
- La coalition list CL serializada → obtiene `CL_CID`

Ambos CIDs se publican junto con la clave pública LMS como el nuevo "bulletin board" (que ahora es sólo un fichero JSON con tres campos: `lmsPublicKey`, `crvCID`, `clCID`).

---

## Fase 3 — Servicio gRPC del Trustee

El trustee se convierte en un servidor gRPC que expone:

```
TrusteeService.Setup(prf_key, cl_cid, cas_url) → OK
TrusteeService.ShardSign1(key_id, message, n, length_chk) → Round1Response
TrusteeService.ShardSign2(R, chk_i, parameters, length_path, I) → Round2Response
```

El método `Setup` se llama una vez durante el setup del Dealer: recibe la clave PRF `K[t]` por canal seguro (en producción, esto sería TLS mutuo; en el prototipo, una variable de entorno o un volumen Docker montado es suficiente), descarga la CL del CAS y puebla la tabla `keylist` en SQLite.

Puntos de atención:
- Los métodos `ShardSign1` y `ShardSign2` deben ser **idempotentes desde el punto de vista del protocolo**, pero no reutilizables: si el aggregator llama dos veces a `Sign1` con el mismo KeyID, el trustee debe devolver `abort=true` la segunda vez.
- El timeout entre `Sign1` y `Sign2` debe ser finito: si el aggregator no llama a `Sign2` en un plazo razonable (p.ej. 30 segundos), el trustee limpia el estado de `signing_state` y libera el KeyID... pero no puede devolverlo al `keylist` porque el papel del protocolo exige que un KeyID usado nunca se reutilice. Esto hay que pensarlo: la consecuencia es que un aggregator malicioso o caído puede "quemar" KeyIDs. Es exactamente el modelo de amenaza descrito en el paper (un aggregator deshonesto puede impedir firmas pero no forjar).

---

## Fase 4 — Refactoring del Aggregator

El `Aggregator` actual recibe el `PublicBulletinBoard` en su constructor. En la versión distribuida pasa a recibir:
- La URL del CAS
- Los CIDs de CRV y CL (del bulletin board JSON)
- Las direcciones gRPC de cada trustee

El flujo de `AggregatorSign` queda:

```
1. Descargar CL del CAS (por CID)
2. Determinar la coalición C[keyID]
3. Para cada trustee t en C[keyID]:
     stub_t.ShardSign1(keyID, message, n, lengthCHK)  // llamada gRPC paralela
4. Reconstruir R y CHK con XOR
5. Para cada trustee t en C[keyID]:
     stub_t.ShardSign2(R, CHK[i], parameters, lengthPATH, I)  // llamada gRPC paralela
6. Descargar CRV[keyID] del CAS
7. Reconstruir PATH, Z y producir ThresholdSignature
```

Las llamadas de la misma ronda (paso 3 y paso 5) son independientes entre trustees y se pueden paralelizar con `CompletableFuture`. Esto es relevante para el rendimiento: el paper describe un esquema de dos rondas donde la segunda ronda sólo puede comenzar cuando **todos** los trustees han completado la primera.

---

## Fase 5 — Dockerización

Con todo lo anterior funcionando y testeado localmente, la dockerización es casi mecánica.

### Estructura de contenedores

```
┌─────────────┐     gRPC      ┌───────────────┐
│  Aggregator │ ────────────► │  Trustee 1    │
│             │               └───────────────┘
│             │     gRPC      ┌───────────────┐
│             │ ────────────► │  Trustee 2    │
│             │               └───────────────┘
│             │     gRPC      ┌───────────────┐
│             │ ────────────► │  Trustee k    │
└──────┬──────┘               └───────────────┘
       │ HTTP
       ▼
┌─────────────┐
│  CAS Server │
└─────────────┘
       ▲ HTTP (solo en setup)
┌─────────────┐
│   Dealer    │  (contenedor efímero: corre setup y termina)
└─────────────┘
```

### `docker-compose.yml` esquemático

```yaml
services:
  cas:
    build: ./cas-server
    ports: ["8080:8080"]
    volumes: ["cas-data:/data"]

  trustee-1:
    build: ./trustee
    environment:
      - TRUSTEE_INDEX=0
      - CAS_URL=http://cas:8080
    volumes: ["trustee1-db:/db"]

  trustee-2:
    build: ./trustee
    environment:
      - TRUSTEE_INDEX=1
      - CAS_URL=http://cas:8080
    volumes: ["trustee2-db:/db"]

  aggregator:
    build: ./aggregator
    environment:
      - CAS_URL=http://cas:8080
      - TRUSTEE_URLS=trustee-1:9090,trustee-2:9090
    ports: ["8081:8081"]

  dealer:
    build: ./dealer
    environment:
      - CAS_URL=http://cas:8080
      - TRUSTEE_URLS=trustee-1:9090,trustee-2:9090
    profiles: ["setup"]  # solo se ejecuta en setup, no en runtime
```

El Dealer se modela como un **contenedor efímero** con `profiles: ["setup"]`: se ejecuta una vez con `docker compose --profile setup run dealer`, realiza el setup completo (genera claves, publica CRV y CL en el CAS, envía las claves PRF a cada trustee vía gRPC con TLS), y termina. A partir de ahí sólo corren CAS, trustees y aggregator.

### Seguridad de la clave PRF en setup

La distribución de `K[t]` al trustee `t` es el momento más delicado. Opciones para el prototipo:
- **Variable de entorno cifrada**: el Dealer cifra `K[t]` con la clave pública del trustee y la monta como secreto Docker.
- **gRPC con TLS mutuo**: el Dealer llama a `TrusteeService.Setup` sobre una conexión TLS donde ambos lados presentan certificado. Es la opción más correcta y no especialmente compleja con la librería gRPC de Java.

---

## Fase 6 — Demo y validación end-to-end

Con todo desplegado, la demo mínima es:

```bash
# 1. Setup (se ejecuta una vez)
docker compose --profile setup run dealer \
  --k 3 --d 64 --coalition-file coalitions.json

# 2. Firma threshold
curl -X POST http://localhost:8081/sign \
  -H "Content-Type: application/octet-stream" \
  --data-binary "mensaje de prueba"
# Responde con la ThresholdSignature serializada

# 3. Verificación estándar LMS
# La ThresholdSignature es una firma LMS estándar: cualquier verificador LMS la acepta
```

La verificación con un verificador LMS estándar (incluso con la implementación de referencia de BouncyCastle) es la prueba más contundente de que el esquema funciona correctamente: la firma generada de forma distribuida es indistinguible de una firma LMS normal.

---

## Resumen del orden de trabajo recomendado

| Fase | Tarea | Complejidad | Prerrequisito |
|------|-------|-------------|---------------|
| 0 | Decidir gRPC + CAS propio + SQLite | Diseño | — |
| 1 | Extraer `CRVStore` y `TrusteeStateStore` | Media | — |
| 1 | Tests de integración con impl. reales | Media | Fase 1 |
| 2 | Servidor CAS HTTP | Baja | — |
| 3 | Servidor gRPC del Trustee | Media | Fases 1, 2 |
| 4 | Refactoring del Aggregator | Media | Fases 1, 2, 3 |
| 5 | Dockerización + docker-compose | Baja | Fases 2, 3, 4 |
| 6 | Demo end-to-end + verificación LMS | Baja | Fase 5 |

El trabajo más delicado es la **Fase 3** (atomicidad del estado del trustee y el manejo correcto del timeout entre rondas) y la **seguridad en el setup** (distribución de `K[t]`). Todo lo demás es ingeniería de integración relativamente directa.