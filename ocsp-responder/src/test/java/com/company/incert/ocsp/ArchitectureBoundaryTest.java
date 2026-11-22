package com.company.incert.ocsp;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

/**
 * ArchUnit architectural boundary rules enforcing clean Modular Monolith domain isolation.
 */
@AnalyzeClasses(
        packages = "com.company.incert.ocsp",
        importOptions = ImportOption.DoNotIncludeTests.class
)
class ArchitectureBoundaryTest {

    @ArchTest
    static final ArchRule coreDomainsMustNotDependOnAuth =
            noClasses().that().resideInAnyPackage(
                    "..ocsp.status..",
                    "..ocsp.responder..",
                    "..ocsp.signing..",
                    "..ocsp.rabbitmq.."
            ).should().dependOnClassesThat().resideInAPackage("..ocsp.auth..");

    @ArchTest
    static final ArchRule coreDomainsMustNotDependOnRabbitMq =
            noClasses().that().resideInAnyPackage(
                    "..ocsp.status..",
                    "..ocsp.responder..",
                    "..ocsp.signing..",
                    "..ocsp.auth.."
            ).should().dependOnClassesThat().resideInAPackage("..ocsp.rabbitmq..");

    @ArchTest
    static final ArchRule sharedMustNotDependOnFeatureDomains =
            noClasses().that().resideInAPackage("..ocsp.shared..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "..ocsp.auth..",
                            "..ocsp.rabbitmq..",
                            "..ocsp.schedule..",
                            "..ocsp.signing..",
                            "..ocsp.status..",
                            "..ocsp.responder..",
                            "..ocsp.dashboard.."
                    );

    @ArchTest
    static final ArchRule domainSlicesMustBeFreeOfCycles =
            slices().matching("com.company.incert.ocsp.(*)..")
                    .should().beFreeOfCycles();
}
