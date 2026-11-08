package com.company.incert.ocsp;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noFields;

class ArchitectureTest {

    private static final JavaClasses classes = new ClassFileImporter()
        .withImportOption(new ImportOption.DoNotIncludeTests())
        .importPackages("com.company.incert.ocsp");

    @Test
    void domainShouldNotDependOnFrameworks() {
        noClasses()
            .that().resideInAPackage("..ocsp.*.domain..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "org.springframework..", "jakarta.persistence..",
                "org.apache.kafka..", "com.github.benmanes..")
            .check(classes);
    }

    @Test
    void applicationShouldNotDependOnAdapters() {
        noClasses()
            .that().resideInAPackage("..ocsp.*.application..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "com.company.incert.ocsp..adapter..")
            .check(classes);
    }

    @Test
    void noFieldInjection() {
        noFields()
            .that().areDeclaredInClassesThat().resideInAPackage("com.company.incert.ocsp..")
            .should().beAnnotatedWith("org.springframework.beans.factory.annotation.Autowired")
            .check(classes);
    }

    @Test
    void controllersShouldNotUseJpaRepositoriesDirectly() {
        noClasses()
            .that().resideInAPackage("..ocsp.*.adapter.in..")
            .and().haveSimpleNameEndingWith("Controller")
            .should().dependOnClassesThat().haveSimpleNameEndingWith("JpaRepository")
            .check(classes);
    }
}
