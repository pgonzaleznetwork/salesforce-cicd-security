#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const xml2js = require('xml2js');

// Simple mapping for supported metadata types
const SUPPORTED_METADATA = {
    PermissionSet: {
        policyFolder: 'permissionsets',
        extension: '.permissionset-meta.xml'
    }
    // Add more types here as needed:
    // 'CustomObject': { policyFolder: 'objects', extension: '.object-meta.xml' }
};

const parser = new xml2js.Parser({
    explicitArray: false,
    ignoreAttrs: false,
    attrkey: '@',
    charkey: '#text'
});

async function convertXmlToJson(xmlFilePath, outputDir) {
    const xmlContent = fs.readFileSync(xmlFilePath, 'utf8');

    return new Promise((resolve, reject) => {
        parser.parseString(xmlContent, (err, result) => {
            if (err) {
                reject(err);
                return;
            }

            const basename = path
                .basename(xmlFilePath)
                .replace(/\..*-meta\.xml$/, '');
            const outputPath = path.join(outputDir, `${basename}.json`);

            fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
            console.log(`  Converted ${path.basename(xmlFilePath)} to JSON`);
            resolve(outputPath);
        });
    });
}

async function main() {
    console.log('🔍 Starting Salesforce Metadata Security Scan...\n');

    // Check if we're in a valid SFDX project
    if (!fs.existsSync('sfdx-project.json')) {
        console.error(
            '❌ This is not a valid SFDX project (sfdx-project.json not found)'
        );
        process.exit(1);
    }

    // Check if .policies directory exists
    if (!fs.existsSync('.policies')) {
        console.log(
            '⚠️  No .policies directory found. Skipping security scan.'
        );
        process.exit(0);
    }

    // Run SGD to get changed files
    console.log('📊 Analyzing changed metadata with SFDX Git Delta...');
    const sgdOutput = 'sgd-output';

    // Create output directory if it doesn't exist
    if (fs.existsSync(sgdOutput)) {
        fs.rmSync(sgdOutput, { recursive: true });
    }
    fs.mkdirSync(sgdOutput, { recursive: true });

    try {
        execSync(
            `sf sgd source delta --to "HEAD" --from "origin/${process.env.GITHUB_BASE_REF || 'main'}" --output "${sgdOutput}" --generate-delta`,
            { stdio: 'inherit' }
        );
    } catch (error) {
        console.error('❌ SFDX Git Delta failed:', error.message);
        process.exit(1);
    }

    // Check if any metadata changed
    const deltaSourcePath = path.join(sgdOutput, 'force-app');
    if (!fs.existsSync(deltaSourcePath)) {
        console.log('✅ No metadata changes detected. Skipping security scan.');
        process.exit(0);
    }

    console.log(
        '🔍 Scanning changed permission sets for security violations...\n'
    );

    const tempDir = 'temp-scan';
    if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true });
    }
    fs.mkdirSync(tempDir, { recursive: true });

    let totalViolations = 0;
    const scanResults = [];

    // Find all permission set files in the delta
    const findPermissionSets = (dir, files = []) => {
        const items = fs.readdirSync(dir, { withFileTypes: true });

        for (const item of items) {
            const itemPath = path.join(dir, item.name);

            if (item.isDirectory()) {
                findPermissionSets(itemPath, files);
            } else if (
                item.isFile() &&
                item.name.endsWith('.permissionset-meta.xml')
            ) {
                files.push(itemPath);
            }
        }

        return files;
    };

    const permissionSetFiles = findPermissionSets(deltaSourcePath);

    if (permissionSetFiles.length === 0) {
        console.log('✅ No permission set changes detected.');
        process.exit(0);
    }

    console.log(
        `Found ${permissionSetFiles.length} changed permission set(s)\n`
    );

    // Process each permission set file
    for (const filePath of permissionSetFiles) {
        console.log(`🔍 Scanning ${path.basename(filePath)}...`);

        try {
            // Convert to JSON
            const jsonPath = await convertXmlToJson(filePath, tempDir);

            // Run all permission set policies
            const policyPath = '.policies/permissionsets';
            if (!fs.existsSync(policyPath)) {
                console.log('  ⚠️  No permission set policies found');
                continue;
            }

            const policyFiles = fs
                .readdirSync(policyPath)
                .filter((f) => f.endsWith('.rego'))
                .map((f) => path.join(policyPath, f));

            if (policyFiles.length === 0) {
                console.log('  ⚠️  No .rego policy files found');
                continue;
            }

            for (const policyFile of policyFiles) {
                console.log(`  Testing against ${path.basename(policyFile)}`);

                try {
                    const result = execSync(
                        `opa eval --data "${policyFile}" --input "${jsonPath}" "data.salesforce.permissionsets"`,
                        { encoding: 'utf8' }
                    );

                    const opaResult = JSON.parse(result);
                    const violations =
                        opaResult.result[0]?.expressions[0]?.value;

                    if (
                        violations &&
                        violations.deny &&
                        Object.keys(violations.deny).length > 0
                    ) {
                        console.log(`    ❌ VIOLATIONS FOUND:`);
                        Object.keys(violations.deny).forEach((violation) => {
                            console.log(`      ${violation}`);
                        });
                        totalViolations += Object.keys(violations.deny).length;

                        scanResults.push({
                            file: filePath,
                            policy: policyFile,
                            violations: Object.keys(violations.deny)
                        });
                    } else {
                        console.log(`    ✅ No violations`);
                    }

                    if (
                        violations &&
                        violations.warn &&
                        Object.keys(violations.warn).length > 0
                    ) {
                        console.log(`    ⚠️  WARNINGS:`);
                        Object.keys(violations.warn).forEach((warning) => {
                            console.log(`      ${warning}`);
                        });
                    }
                } catch (opaError) {
                    console.log(
                        `    ⚠️  Policy execution failed: ${opaError.message}`
                    );
                }
            }
        } catch (conversionError) {
            console.log(
                `  ⚠️  Failed to convert ${filePath}: ${conversionError.message}`
            );
        }

        console.log('');
    }

    // Cleanup
    if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true });
    }
    if (fs.existsSync(sgdOutput)) {
        fs.rmSync(sgdOutput, { recursive: true });
    }

    // Final results
    console.log('='.repeat(60));
    console.log('📊 METADATA SECURITY SCAN RESULTS');
    console.log('='.repeat(60));

    if (totalViolations === 0) {
        console.log('✅ No security violations detected!');
        console.log(
            'All permission set changes comply with security policies.'
        );
        process.exit(0);
    } else {
        console.log(`❌ Found ${totalViolations} security violations:`);
        console.log('');

        scanResults.forEach((result) => {
            console.log(`📄 ${result.file}`);
            console.log(`📋 Policy: ${result.policy}`);
            result.violations.forEach((violation) => {
                console.log(`  ❌ ${violation}`);
            });
            console.log('');
        });

        console.log('🚫 Pull Request BLOCKED due to security violations.');
        console.log('Please fix the violations above before merging.');
        process.exit(1);
    }
}

if (require.main === module) {
    main().catch((error) => {
        console.error('❌ Scanner failed:', error);
        process.exit(1);
    });
}
