package es.uma.nicslab.hbs.lms;

public interface LMSContextBasedSigner
{
    LMSContext generateLMSContext();

    byte[] generateSignature(LMSContext context);

    long getUsagesRemaining();
}
