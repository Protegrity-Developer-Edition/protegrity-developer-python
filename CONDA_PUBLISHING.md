# Publishing protegrity-developer-python to Conda

This guide provides instructions for building and publishing the `protegrity-developer-python` package to Anaconda.org (conda) under the Protegrity organization.

## Prerequisites

Before you begin, ensure you have the following installed:

1. **Anaconda or Miniconda**
   ```bash
   # Download and install from: https://docs.conda.io/en/latest/miniconda.html
   ```

2. **conda-build**
   ```bash
   conda install conda-build
   ```

3. **anaconda-client** (for uploading to Anaconda.org)
   ```bash
   conda install anaconda-client
   ```

4. **Account Setup**
   - Create an account at https://anaconda.org
   - Create or join the "Protegrity" organization on Anaconda.org
   - Get appropriate permissions to publish packages under the organization

## Building the Conda Package

### Step 1: Navigate to the Project Root

```bash
cd /home/yigalr/projects/pty-dev
```

### Step 2: Build the Package

Build the conda package using the recipe in the `conda-recipe/` directory:

```bash
conda build conda-recipe/
```

This will:
- Download the source from PyPI (or use local source if configured)
- Create the conda package
- Run tests to verify the package works correctly
- Output the package location (typically in your conda-bld directory)

### Step 3: Verify the Build

After a successful build, conda-build will display the path to the created package, something like:
```
anaconda upload /path/to/conda-bld/noarch/protegrity-developer-python-1.0.0-py_0.tar.bz2
```

You can test the package locally before uploading:

```bash
# Create a test environment
conda create -n test-protegrity python=3.12

# Activate the environment
conda activate test-protegrity

# Install the locally built package
conda install --use-local protegrity-developer-python

# Test the import
python -c "import protegrity_developer_python; import appython; print('Success!')"

# Clean up
conda deactivate
conda env remove -n test-protegrity
```

## Publishing to Anaconda.org

### Step 1: Login to Anaconda.org

```bash
anaconda login
```

Enter your Anaconda.org credentials when prompted.

### Step 2: Upload the Package

Upload the package to the Protegrity organization channel:

```bash
anaconda upload -u Protegrity /path/to/conda-bld/noarch/protegrity-developer-python-1.0.0-py_0.tar.bz2
```

Replace `/path/to/conda-bld/noarch/protegrity-developer-python-1.0.0-py_0.tar.bz2` with the actual path from your build output.

**Options:**
- Add `--force` to overwrite an existing package version
- Add `--label main` to publish to the main channel (default)
- Add `--label dev` to publish to a development channel

### Step 3: Verify the Upload

Visit your package page:
```
https://anaconda.org/Protegrity/protegrity-developer-python
```

## Installing the Published Package

Once published, users can install the package using:

```bash
# Install from the Protegrity channel
conda install -c Protegrity protegrity-developer-python

# Or add the channel permanently
conda config --add channels Protegrity
conda install protegrity-developer-python
```

## Building from Local Source (Alternative)

If you want to build from local source instead of PyPI:

1. Edit `conda-recipe/meta.yaml` and uncomment the `path: ..` line in the `source` section
2. Comment out or remove the `url` line
3. Run the build command from the project root:
   ```bash
   conda build conda-recipe/
   ```

## Updating the Package

To publish a new version:

1. Update the version in `pyproject.toml`
2. Update the version in `conda-recipe/meta.yaml`
3. Increment the build number in `meta.yaml` if needed (for same version but different build)
4. Rebuild and upload following the steps above

## Troubleshooting

### Build Failures

- **Missing dependencies**: Ensure all dependencies are available in conda channels
- **Test failures**: Check the test section in `meta.yaml`
- **Python version issues**: Verify the Python version constraints

### Upload Issues

- **Authentication failed**: Run `anaconda login` again
- **Permission denied**: Ensure you have upload permissions for the Protegrity organization
- **Package exists**: Use `--force` flag to overwrite, or increment the build number

### Getting Help

- Conda build documentation: https://docs.conda.io/projects/conda-build/
- Anaconda.org documentation: https://docs.anaconda.com/anacondaorg/

## CI/CD Integration (Optional)

For automated publishing, you can integrate conda builds into your CI/CD pipeline:

```yaml
# Example GitHub Actions workflow snippet
- name: Build conda package
  run: |
    conda install conda-build anaconda-client
    conda build conda-recipe/

- name: Upload to Anaconda
  env:
    ANACONDA_TOKEN: ${{ secrets.ANACONDA_TOKEN }}
  run: |
    anaconda -t $ANACONDA_TOKEN upload -u Protegrity /path/to/package/*.tar.bz2
```

Store your Anaconda token as a secret in your CI/CD system.

## Package Maintenance

- Regularly update dependencies
- Test against new Python versions
- Monitor user feedback and issues
- Keep documentation up to date
- Follow semantic versioning for releases

## Support

For issues specific to the conda package, please file an issue at:
https://github.com/Protegrity-Developer-Edition/protegrity-developer-python/issues
