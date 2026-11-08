package com.company.incert.ocsp;

import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModules;
import org.springframework.modulith.docs.Documenter;

class ModularityTest {

    private static final ApplicationModules modules =
        ApplicationModules.of(OcspApplication.class);

    @Test
    void verifyModuleStructure() {
        modules.verify();
    }

    @Test
    void writeModuleDocumentation() {
        new Documenter(modules)
            .writeModulesAsPlantUml()
            .writeIndividualModulesAsPlantUml();
    }
}

