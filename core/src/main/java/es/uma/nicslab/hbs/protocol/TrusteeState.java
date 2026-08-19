package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.protocol.SigningState;

/**
 * Abstracción del estado operacional del Trustee.
 *
 * Gestiona dos responsabilidades:
 *
 * 1. KeyList — los KeyIDs que este trustee puede usar todavía.
 *    Se puebla en Setup y se vacía conforme se firman mensajes.
 *    La operación claimKeyID es atómica: comprueba si el KeyID está
 *    disponible y lo elimina en una sola operación, evitando condiciones
 *    de carrera y la reutilización de KeyIDs.
 *
 * 2. SigningState — estado entre Round1 y Round2.
 *    Cuando el Trustee acepta una firma en Round1, guarda el keyID
 *    y el mensaje en curso. El estado se mantiene de forma independiente
 *    por KeyID, por lo que pueden existir varias firmas concurrentes para
 *    KeyIDs distintos. Round2 recupera y borra atómicamente el estado
 *    correspondiente al KeyID solicitado.
 *
 * Implementaciones:
 *  - InMemoryTrusteeStateStore → tests unitarios de core
 *  - SQLiteTrusteeStateStore → producción en trustee-server
 */
public interface TrusteeState {

    /**
     * Inicializa la keyList con los KeyIDs que pertenecen a este trustee.
     * Se llama una vez durante el Setup.
     *
     * @param keyIDs Array de KeyIDs asignados a este trustee.
     */
    void initKeyList(int[] keyIDs) throws Exception;

    /**
     * Intenta reclamar un KeyID para usarlo en una firma.
     * Si el KeyID está disponible, lo elimina de la keyList y devuelve true.
     * Si no está disponible (ya usado o nunca asignado), devuelve false.
     *
     * Esta operación debe ser atómica: comprobar y eliminar en una
     * sola operación para evitar condiciones de carrera.
     *
     * @param keyID KeyID a reclamar.
     * @return true si el KeyID estaba disponible y ha sido reclamado.
     */
    boolean claimKeyID(int keyID) throws Exception;

    /**
     * Guarda el estado entre Round1 y Round2.
     * Puede existir como máximo un estado activo por KeyID.
     *
     * @param keyID   KeyID en curso (bytes).
     * @param message Mensaje a firmar.
     */
    void saveSigningState(int keyID, byte[] message) throws Exception;

    /**
     * Recupera el estado entre rondas y lo borra en una sola operación.
     * Devuelve null si no hay ninguna firma en curso.
     *
     * La atomicidad de leer+borrar es importante: evita que Round2
     * pueda ejecutarse dos veces con el mismo estado.
     *
     * @return SigningState con keyID y message, o null si no hay firma en curso.
     */
    SigningState loadAndClearSigningState(int keyID) throws Exception;

    /**
     * Indica si hay una firma en curso para el KeyID indicado.
     */
    boolean hasSigningState(int keyID) throws Exception;

}