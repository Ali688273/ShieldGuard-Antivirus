pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(org.gradle.api.initialization.resolve.RepositoriesMode.FAIL_ON_PROJECT_REPOSITORIES)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "ShieldGuard-Antivirus"
include(":app")
