package com.here.provenanceanalyzer.downloader

import ch.frankel.slf4k.*

import com.here.provenanceanalyzer.util.ProcessCapture
import com.here.provenanceanalyzer.util.log

import com.vdurmont.semver4j.Semver

import java.io.File
import java.io.IOException

object GitRepo : VersionControlSystem() {

    /**
     * Clones the Git repositories defined in the manifest file using the Git Repo tool.
     *
     * @param vcsPath The path to the repo manifest file in the repository. Defaults to "manifest.xml" if not provided.
     *
     * @throws DownloadException In case the download failed.
     */
    override fun download(vcsUrl: String, vcsRevision: String?, vcsPath: String?, version: Semver, targetDir: File)
            : String {
        val revision = if (vcsRevision != null && vcsRevision.isNotEmpty()) vcsRevision else "master"
        val manifestPath = if (vcsPath != null && vcsPath.isNotEmpty()) vcsPath else "manifest.xml"

        try {
            log.debug { "Initialize git-repo from $vcsUrl with branch $revision and manifest $manifestPath." }
            runRepoCommand(targetDir, "init", "--depth", "1", "-b", revision, "-u", vcsUrl, "-m", manifestPath)

            log.debug { "Start git-repo sync." }
            runRepoCommand(targetDir, "sync", "-c")
            return getManifestRevision(targetDir)
        } catch (e: IOException) {
            throw DownloadException("Could not clone $vcsUrl/$manifestPath", e)
        }
    }

    private fun getManifestRevision(targetDir: File): String {
        val revision = ProcessCapture(File(targetDir, ".repo/manifests"), "git", "rev-parse", "HEAD").requireSuccess()
                .stdout().trim()
        println("Checked out manifest revision $revision.")
        return revision
    }

    override fun isApplicableProvider(vcsProvider: String) =
            vcsProvider.toLowerCase() in listOf("gitrepo", "git-repo", "repo")

    override fun isApplicableUrl(vcsUrl: String) = false

    private fun runRepoCommand(targetDir: File, vararg args: String) {
        ProcessCapture(targetDir, "repo", *args).requireSuccess()
    }

}
