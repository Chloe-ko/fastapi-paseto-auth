## Sharing feedback

This project is still relatively new and probably has flaws, both in terms of internal usability as well as code quality.\
I have tried my best to however make sure that it is as secure as it can be.\
I also do not yet have a complete understanding of the project, especially the CI/CD and tests. If you find something I missed to adjust, please feel free to let me know.

If you have suggestions for improvements or want to help, feel free to <a href="https://github.com/Chloe-ko/fastapi-paseto-auth/issues/new" target="_blank">open an issue</a> or create a PR with your modifications.

## Developing

If you already cloned the repository and you know that you need to deep dive in the code, here are some guidelines to set up your environment.

This project uses VS Code Development containers.
With the <a href="https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers" target="_blank">Remote - Containers</a> extension installed in VSCode, and Docker installed on your device, VSCode should automatically prompt you about having found a development container configuration file and offer you to open the project in the container.

If not, you can always press F1 and manually click "Remote-Containers: Open Folder in Container" and select the source of this repo that contains the .devcontainer folder.

Any development dependencies will be automatically installed.

You might need to select the correct python interpreter after opening it in container, as VS Code defaults to using the system-wide interpreter, rather than the one set up by Pipenv.

**Using your local FastAPI PASETO Auth**

If you create a Python file that imports and uses FastAPI PASETO Auth, and run it with the Python from your local environment, it will use your localFastAPI PASETO Auth source code.

That way, you don't have to "install" your local version to be able to test every change.

## Docs

The documentation uses <a href="https://www.mkdocs.org/" class="external-link" target="_blank">MkDocs</a>.

All the documentation is in Markdown format in the directory `./docs`.

Many of the sections in the User Guide have blocks of code.

In fact, those blocks of code are not written inside the Markdown, they are Python files in the `./examples/` directory.

And those Python files are included/injected in the documentation when generating the site.

### Docs for tests

Most of the tests actually run against the example source files in the documentation.

This helps making sure that:

* The documentation is up to date.
* The documentation examples can be run as is.
* Most of the features are covered by the documentation, ensured by test coverage.

During local development, there is a script that builds the site and checks for any changes, live-reloading:

```bash
$ bash scripts/docs-live.sh
```

It will serve the documentation on `http://0.0.0.0:5000`.

That way, you can edit the documentation/source files and see the changes live.

## Tests

There is a script that you can run locally to test all the code and generate coverage reports in HTML:

```bash
$ bash scripts/tests.sh
```

This command generates a directory `./htmlcov/`, if you open the file `./htmlcov/index.html` in your browser, you can explore interactively the regions of code that are covered by the tests, and notice if there is any region missing.
