package es.uma.nicslab.hbs.trustee;

import es.uma.nicslab.hbs.protocol.TrusteeState;
import es.uma.nicslab.hbs.protocol.SigningState;

import java.sql.*;

/**
 * Implementación SQLite de TrusteeStateStore.
 *
 * Persiste el estado operacional del trustee en dos tablas:
 *
 *   keylist       — KeyIDs disponibles para este trustee.
 *                   Se puebla en Setup y se vacía conforme se usan.
 *
 *   signing_state — Estado entre Round1 y Round2.
 *                   Solo puede existir una fila (id=1), por diseño
 *                   del protocolo: el trustee es estrictamente secuencial
 *                   (comprobación current ≠ None).
 *
 * La clave PRF K NO se almacena aquí. Es material criptográfico sensible
 * que se gestiona fuera de la base de datos (secreto Docker o fichero cifrado).
 *
 * Thread-safety: los métodos críticos usan synchronized para garantizar
 * atomicidad a nivel de JVM, complementando las garantías de SQLite.
 */
public class SQLiteTrusteeState implements TrusteeState {

    private static final int SIGNING_STATE_ID = 1;

    private final Connection conn;

    /**
     * Abre (o crea) la base de datos SQLite en la ruta indicada
     * e inicializa el esquema si no existe.
     *
     * @param dbPath Ruta al fichero SQLite, p.ej. "/db/trustee.db".
     *               Usar ":memory:" para tests en memoria.
     */
    public SQLiteTrusteeState(String dbPath) throws SQLException {
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        this.conn.setAutoCommit(true);
        initSchema();
    }

    private void initSchema() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS keylist (
                    key_id INTEGER PRIMARY KEY
                )
                """);
            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS signing_state (
                    id      INTEGER PRIMARY KEY CHECK (id = 1),
                    key_id  BLOB    NOT NULL,
                    message BLOB    NOT NULL,
                    created INTEGER NOT NULL
                )
                """);
        }
    }

    @Override
    public void initKeyList(int[] keyIDs) throws SQLException {
        // Borramos cualquier estado previo e insertamos los nuevos KeyIDs
        // en una única transacción para garantizar consistencia.
        conn.setAutoCommit(false);
        try (Statement st = conn.createStatement()) {
            st.executeUpdate("DELETE FROM keylist");
        }
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO keylist (key_id) VALUES (?)")) {
            for (int keyID : keyIDs) {
                ps.setInt(1, keyID);
                ps.addBatch();
            }
            ps.executeBatch();
        }
        conn.commit();
        conn.setAutoCommit(true);
    }

    /**
     * Intenta reclamar un KeyID de forma atómica.
     *
     * Usa DELETE y comprueba el número de filas afectadas: si era 1,
     * el KeyID estaba disponible y ha sido eliminado. Si era 0, no estaba.
     * SQLite garantiza que esta operación es atómica.
     */
    @Override
    public synchronized boolean claimKeyID(int keyID) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "DELETE FROM keylist WHERE key_id = ?")) {
            ps.setInt(1, keyID);
            return ps.executeUpdate() == 1;
        }
    }

    /**
     * Guarda el estado entre Round1 y Round2.
     *
     * Usa INSERT OR REPLACE sobre id=1, la única fila permitida.
     * Si ya existía una fila (estado corrupto por crash), la sobreescribe.
     */
    @Override
    public synchronized void saveSigningState(byte[] keyID, byte[] message) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                INSERT OR REPLACE INTO signing_state (id, key_id, message, created)
                VALUES (?, ?, ?, ?)
                """)) {
            ps.setInt(1, SIGNING_STATE_ID);
            ps.setBytes(2, keyID);
            ps.setBytes(3, message);
            ps.setLong(4, System.currentTimeMillis() / 1000L);
            ps.executeUpdate();
        }
    }

    /**
     * Lee el estado entre rondas y lo borra en una única transacción.
     *
     * La atomicidad de leer+borrar es crítica: evita que Round2 pueda
     * ejecutarse dos veces con el mismo estado si hay un error de red.
     *
     * @return SigningState con keyID y message, o null si no hay firma en curso.
     */
    @Override
    public synchronized SigningState loadAndClearSigningState() throws SQLException {
        conn.setAutoCommit(false);
        try {
            SigningState state = null;

            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT key_id, message FROM signing_state WHERE id = ?")) {
                ps.setInt(1, SIGNING_STATE_ID);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        byte[] keyID = rs.getBytes("key_id");
                        byte[] message = rs.getBytes("message");
                        state = new SigningState(keyID, message);
                    }
                }
            }

            if (state != null) {
                try (PreparedStatement ps = conn.prepareStatement(
                        "DELETE FROM signing_state WHERE id = ?")) {
                    ps.setInt(1, SIGNING_STATE_ID);
                    ps.executeUpdate();
                }
            }

            conn.commit();
            return state;

        } catch (SQLException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(true);
        }
    }

    @Override
    public synchronized boolean hasSigningState() throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT 1 FROM signing_state WHERE id = ?")) {
            ps.setInt(1, SIGNING_STATE_ID);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Cierra la conexión con la base de datos.
     * Llamar al finalizar el proceso o en tests con @AfterEach.
     */
    public void close() throws SQLException {
        if (conn != null && !conn.isClosed()) {
            conn.close();
        }
    }
}