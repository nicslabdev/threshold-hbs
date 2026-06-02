package es.uma.nicslab.hbs.protocol;

/**
 * Estado guardado entre Round1 y Round2.
 */
public record SigningState(int keyID, byte[] message) {}
