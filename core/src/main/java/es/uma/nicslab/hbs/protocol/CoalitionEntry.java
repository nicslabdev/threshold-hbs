package es.uma.nicslab.hbs.protocol;

/**
 * Entrada de la Coalition List para un KeyID concreto.
 *
 * Agrupa dos datos:
 *  - trustees: índices de los trustees que forman la coalición para este KeyID.
 *  - crvCid: CID del CRV asociado a este KeyID en el CAS.
 *
 * El Dealer construye un array de CoalitionEntry[] (uno por KeyID) durante
 * el Setup y lo publica en el CAS via CASWriter.
 * El Aggregator lo descarga via CASReader para saber a qué trustees
 * contactar y qué CRV usar en cada firma.
 */
public record CoalitionEntry(int[] trustees, String crvCid) {}