package com.company.incert.kms;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noFields;

class ArchitectureTest {

    private static final JavaClasses classes = new ClassFileImporter()
            .importPackages("com.company.incert.kms");

    @Test
    void domainShouldNotDependOnSpringOrJpa() {
        noClasses()
                .that().resideInAPackage("..kms.domain..")
                .should().dependOnClassesThat().resideInAnyPackage(
                        "org.springframework..", "jakarta.persistence..", "org.springframework.amqp..")
                .check(classes);
    }

    @Test
    void applicationShouldNotDependOnAdapters() {
        noClasses()
                .that().resideInAPackage("..kms.application..")
                .should().dependOnClassesThat().resideInAPackage("..kms.adapter..")
                .check(classes);
    }

    @Test
    void noFieldInjectionAllowed() {
        noFields()
                .that().areDeclaredInClassesThat().resideInAPackage("com.company.incert.kms..")
                .should().beAnnotatedWith("org.springframework.beans.factory.annotation.Autowired")
                .check(classes);
    }
}
