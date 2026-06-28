## Description

<!-- Provide a clear and concise description of your changes -->

## Type of Change

<!-- Mark the relevant option with an 'x' -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Code refactoring (no functional changes)
- [ ] Performance improvement
- [ ] Dependency update
- [ ] Other (please describe):

## Related Issue

<!-- Link to the issue this PR addresses -->

Fixes #(issue number)
Closes #(issue number)
Related to #(issue number)

## Motivation and Context

<!-- Why is this change needed? What problem does it solve? -->

## Changes Made

<!-- List the specific changes you made -->

-
-
-

## Testing Performed

<!-- Describe the tests you ran to verify your changes -->

**Test Environment:**
- OS: <!-- e.g., Arch Linux -->
- Kernel: <!-- e.g., 6.5.0 -->
- Python: <!-- e.g., 3.11.5 -->

**Tests Conducted:**
- [ ] Tested on fresh installation
- [ ] Tested start/stop functionality
- [ ] Tested with default parameters
- [ ] Tested with custom parameters (--ttl, --ports, etc.)
- [ ] Verified iptables rules are created correctly
- [ ] Verified DNS configuration changes work
- [ ] Verified cleanup (--stop) works properly
- [ ] Tested systemd service integration (if applicable)
- [ ] Tested in VM or isolated environment
- [ ] Other (describe):

**Manual Test Commands:**
```bash
# Commands you used to test
sudo whydpi start
# etc.
```

**Test Results:**
<!-- Describe what happened when you tested -->

## Impact Assessment

**Components Affected:**
- [ ] DNS configuration (`dns_config.py`)
- [ ] Packet injection (`packet_injector.py`)
- [ ] NFQUEUE handling (`nfqueue_handler.py`)
- [ ] Configuration (`config.py`)
- [ ] CLI interface (`__main__.py`)
- [ ] Installation script (`install.sh`)
- [ ] Systemd service
- [ ] Documentation
- [ ] Dependencies

**Backward Compatibility:**
- [ ] This change is fully backward compatible
- [ ] This change has minor compatibility implications (please explain below)
- [ ] This is a breaking change (please explain below)

**Compatibility Details:**
<!-- If not fully backward compatible, explain the implications -->

## Code Quality

- [ ] My code follows the project's style guidelines (PEP 8)
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have added docstrings to new functions/classes
- [ ] My changes generate no new warnings or errors
- [ ] I have added tests that prove my fix is effective or that my feature works (when applicable)
- [ ] New and existing unit tests pass locally with my changes (when applicable)

## Documentation

- [ ] I have updated the README.md (if needed)
- [ ] I have updated relevant docstrings
- [ ] I have added/updated comments for complex logic
- [ ] I have updated CONTRIBUTING.md (if needed)
- [ ] I have added usage examples (if adding a feature)
- [ ] No documentation changes needed

**Documentation Changes:**
<!-- List any documentation updates you made -->

## Security Considerations

- [ ] This change does not introduce new security risks
- [ ] I have considered security implications
- [ ] I have added appropriate input validation
- [ ] I have avoided hardcoding sensitive data
- [ ] This change has been tested for privilege escalation vulnerabilities
- [ ] Security concerns (describe below):

**Security Notes:**
<!-- Describe any security considerations or concerns -->

## Educational Value

<!-- How does this PR contribute to whyDPI's educational goals? -->

- [ ] Helps users understand DPI bypass techniques better
- [ ] Demonstrates new security concepts
- [ ] Improves troubleshooting and learning
- [ ] Expands platform/distribution support
- [ ] Enhances code clarity and documentation
- [ ] Other:

## Screenshots / Output (if applicable)

<!-- Add screenshots, terminal output, or logs demonstrating your changes -->

```
# Terminal output examples
```

## Additional Notes

<!-- Any additional information reviewers should know -->

## Checklist

- [ ] I have read the [CONTRIBUTING](https://github.com/byrdltd/whyDPI/blob/main/CONTRIBUTING.md) document
- [ ] I have read the [CODE_OF_CONDUCT](https://github.com/byrdltd/whyDPI/blob/main/CODE_OF_CONDUCT.md)
- [ ] My commit messages are clear and descriptive
- [ ] I have tested this change thoroughly
- [ ] I have updated documentation as needed
- [ ] This PR focuses on a single concern (not multiple unrelated changes)
- [ ] I understand this project is for educational purposes

## Post-Merge Tasks (if applicable)

<!-- List any tasks that need to be done after this PR is merged -->

- [ ] Update changelog
- [ ] Create release notes
- [ ] Update examples
- [ ] Announce changes to users
- [ ] Other:

---

**For Reviewers:**

Please verify:
- [ ] Code quality and style compliance
- [ ] Tests pass (when test framework is available)
- [ ] Documentation is clear and complete
- [ ] Security considerations are addressed
- [ ] Educational value aligns with project goals
- [ ] No breaking changes without proper justification
