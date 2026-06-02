package es.uma.nicslab.hbs.trustee;

import es.uma.nicslab.hbs.protocol.SigningState;
import es.uma.nicslab.hbs.protocol.TrusteeState;
import es.uma.nicslab.hbs.util.ByteUtils;

import java.sql.*;

public class SQLiteTrusteeState implements TrusteeState {

    private final Connection conn;

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
            // AHORA: key_id es la clave primaria. El estado soporta concurrencia multi-KeyID.
            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS signing_state (
                    key_id  INTEGER PRIMARY KEY,
                    message BLOB    NOT NULL,
                    created INTEGER NOT NULL
                )
                """);
        }
    }

    public void initKeyList(int[] keyIDs) throws SQLException {
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

    public synchronized boolean claimKeyID(int keyID) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "DELETE FROM keylist WHERE key_id = ?")) {
            ps.setInt(1, keyID);
            return ps.executeUpdate() == 1;
        }
    }

    public synchronized void saveSigningState(int keyID, byte[] message) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                INSERT OR REPLACE INTO signing_state (key_id, message, created)
                VALUES (?, ?, ?)
                """)) {
            ps.setInt(1, keyID);
            ps.setBytes(2, message);
            ps.setLong(3, System.currentTimeMillis());
            ps.executeUpdate();
        }
    }

    public synchronized SigningState loadAndClearSigningState(int keyID) throws SQLException {
        conn.setAutoCommit(false);
        try {
            SigningState state = null;

            // Buscamos el estado específico para ESTE keyID
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT message FROM signing_state WHERE key_id = ?")) {
                ps.setInt(1, keyID);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        byte[] message = rs.getBytes("message");
                        state = new SigningState(keyID, message);
                    }
                }
            }

            // Si existe, lo borramos inmediatamente (Read-and-Delete atómico por KeyID)
            if (state != null) {
                try (PreparedStatement ps = conn.prepareStatement(
                        "DELETE FROM signing_state WHERE key_id = ?")) {
                    ps.setInt(1, keyID);
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

    public synchronized boolean hasSigningState(int keyID) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT 1 FROM signing_state WHERE key_id = ?")) {
            ps.setInt(1, keyID);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    public synchronized void purgeExpiredSessions(long timeoutMillis) throws SQLException {
        long boundary = System.currentTimeMillis() - timeoutMillis;
        try (PreparedStatement ps = conn.prepareStatement(
                "DELETE FROM signing_state WHERE created < ?")) {
            ps.setLong(1, boundary);
            ps.executeUpdate();
        }
    }

    public void close() throws SQLException {
        if (conn != null && !conn.isClosed()) {
            conn.close();
        }
    }
}