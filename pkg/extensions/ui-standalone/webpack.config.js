const path = require('path');
const webpack = require('webpack');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const fs = require('fs');

// -------
// OUTPUT
// -------

const PUBLIC_FOLDER = 'public';
const OUTPUT_FOLDER = 'build';
const SRC_FOLDER = 'src';
const ACI_UI_ASSETS = 'UIAssets';
const ACI_APP_START = 'index.html';
let dirPrefix = '';

const IS_PRODUCTION = process.env.NODE_ENV && process.env.NODE_ENV.indexOf('production') !== -1;
const IS_DEVELOPMENT = !IS_PRODUCTION;
const IS_BOOTSTRAP = process.env.NODE_ENV && process.env.NODE_ENV.indexOf('bootstrap') !== -1;
if (IS_BOOTSTRAP) {
    // for index.html, index.js, and build folder
    dirPrefix = 'bootstrap/';
}

// const appJson = JSON.parse(fs.readFileSync('./public/' + ACI_APP_TEMPLATE + '/app.json', 'utf-8'));

let endpointConfig = {
    IS_APIC_DEV_MODE: true,
    BASE_NATIVE_URI: '/api',
    APIC_DEV_SETTINGS: { // contains defaults
        URI: '', // full APIC uri
        USERNAME: '', // <-- add credentials here
        PASSWORD: '' // <-- add credentials here
    }
};
endpointConfig.BASE_URI = '/appcenter/Cisco/' + endpointConfig.APP_ID + '/api';

if (IS_DEVELOPMENT) {
    endpointConfig = Object.assign({}, endpointConfig, {
        IS_APIC_DEV_MODE: true,
        BASE_NATIVE_URI: '/apicProxy',
        BASE_URI: 'https://172.16.176.28/api',
        APIC_DEV_SETTINGS: { // contains defaults
            URI: 'https://172.16.176.28', // full APIC uri
            USERNAME: 'admin', // <-- add credentials here
            PASSWORD: 'ins3965!' // <-- add credentials here
        }
    });
}

let env = {
    production: IS_PRODUCTION,
    development: IS_DEVELOPMENT,
    // appConfig: {
    //     APP_ID: appJson.appid,
    //     SIGNATURE: appJson.signature,
    //     NAME: appJson.name,
    //     TITLE: appJson.title,
    //     VERSION: appJson.version
    // },
    endpointConfig: endpointConfig
}

// expose env to runtime code
// env is exposed via js file.  @see endpoint.js url construction
fs.writeFileSync('./' + SRC_FOLDER + '/appEnv.js', 'const ENV = '.concat(JSON.stringify(env), '; export {ENV};'), {flag: 'w+'});


// -------
// ENTRY
// -------
const entry = [
    'whatwg-fetch',
    path.resolve(dirPrefix + SRC_FOLDER, 'index.js')
];

if(IS_DEVELOPMENT) {
    entry.unshift('react-hot-loader/patch');
}

const output = {
    path: path.resolve(dirPrefix + OUTPUT_FOLDER, ACI_UI_ASSETS),
    filename: 'index.[hash].js'
};

// ----------
// RESOLVE
// ----------

const resolve = {
    extensions: ['.js', '.jsx'],
    modules: [path.resolve(__dirname), 'node_modules', 'bower_components'],
    symlinks: false // This is required from webpack to exclude linked modules together with node_modules (e.g. eslint won't analyse these modules)
};

// ----------
// RULES
// ----------

// Shared rules
let rulesInclude = [path.resolve(SRC_FOLDER)];
if (dirPrefix) {
    rulesInclude.push(path.resolve(dirPrefix + SRC_FOLDER));
}
const rules = [
    {
        test: /\.(js|jsx)$/,
        include: rulesInclude,
        exclude: /(node_modules|bower_components)/,
        use: ['babel-loader',
            {
                loader: 'eslint-loader',
                options: {
                    sourceMap: IS_DEVELOPMENT,
                    failOnWarning: false,
                    failOnError: true,
                    fix: true,
                    emitWarning: false,
                }
            }
        ]
    }
];

let getCSSLoaders = (enableCSSModule) => {
    const loaders = [];
    loaders.push({
        loader: 'style-loader'
    });

    loaders.push({
        loader: MiniCssExtractPlugin.loader,
        options: {
            hmr: process.env.NODE_ENV === 'development',
        }
    });

    const cssLoaderConfig = {
        loader: 'css-loader',
        options: {
            sourceMap: IS_DEVELOPMENT,
            minimize: false
        }
    };

    loaders.push(cssLoaderConfig);
    loaders.push(
        {
            loader: 'sass-loader',
            options: {sourceMap: IS_DEVELOPMENT}
        }
    );

    return loaders;
};

rules.push({
    test: /\.(sa|sc|c)ss$/,
    use: getCSSLoaders(),
});

// Loader for all external files (e.g. font or image files)
rules.push({
    test: /\.(woff|woff2|eot|ttf|jpg|png|svg)$/,
    use: [
        {
            loader: 'file-loader',
            options: {
                name: 'static/[name]-[hash].[ext]'
            }
        }
    ]
});

// -------
// DEV SERVER
// -------

const proxyConfig = {
    changeOrigin: true,
    secure: false,
    logLevel: 'debug'
};

// https://ifav34-ifc1.insieme.local,
// QA -ifav19-ifc1.insieme.local, PFMS Apis - https://tel1-ifc1.insieme.local
// https://uidev1-ifc1.insieme.local;
// https://172.25.124.160,
// https://ifav201-apic1.insieme.local

// const target = 'https://172.31.157.77';
// const target = 'https://ifav74-se-ova4.cisco.com';
const target = 'http://172.31.140.203:5000';
// const target = 'https://ifav19-sn3.insieme.local';

let devPort = 3001;
if (IS_BOOTSTRAP) {
    devPort = 3022;
}

const devServer = {
    contentBase: path.resolve(dirPrefix + OUTPUT_FOLDER, ACI_UI_ASSETS),
    publicPath: '/',
    port: devPort,
    hot: true,
    open: true, // open browser
    openPage: '',
    historyApiFallback: {
        index: dirPrefix + '/index.html'
    },
    proxy: {
        '/api': Object.assign({}, proxyConfig, {target: target}),
        '/appcenter': Object.assign({}, proxyConfig, {target: target}),
        '/sedgeapi': Object.assign({}, proxyConfig, {target: target}),
        '/': Object.assign({}, proxyConfig, {target: target}),
    }
};

// -------
// PLUGINS
// -------

const HtmlWebpackPlugin = require('html-webpack-plugin');
const HtmlWebpackPluginConfig = new HtmlWebpackPlugin({
    template: path.resolve(dirPrefix + PUBLIC_FOLDER, 'index.html'),
    filename: ACI_APP_START,
    inject: 'body',
    // favicon: SRC_FOLDER + '/static/icons/favicon.svg'
});

const CopyWebpackPlugin = require('copy-webpack-plugin');
const CopyWebpackPluginConfig = new CopyWebpackPlugin([
    // {from: path.resolve(PUBLIC_FOLDER, 'icons/icon.png'), to: path.resolve(dirPrefix + OUTPUT_FOLDER, ACI_UI_ASSETS)},
    // {from: path.resolve(PUBLIC_FOLDER, ACI_APP_TEMPLATE), to: path.resolve(dirPrefix + OUTPUT_FOLDER)}
]);

const MiniCssExtractPluginConfig = new MiniCssExtractPlugin({
    filename: '[name].[hash].css',
    chunkFilename: 'index.[hash].js',
});

const LoaderOptionsPlugin = new webpack.LoaderOptionsPlugin({ options: {} });

const plugins = [
    HtmlWebpackPluginConfig,
    CopyWebpackPluginConfig,
    MiniCssExtractPluginConfig,
    LoaderOptionsPlugin
];

if (IS_PRODUCTION) {
    // Temporary disabled Uglify since is not fully compatible with some ES6 syntax like ('target.new' in 'src/common/lang.js')
    // plugins.push(new webpack.optimize.UglifyJsPlugin());
} else {
    plugins.push(new webpack.HotModuleReplacementPlugin());
}

const devtool = 'source-map';
//inline-source--map

module.exports = {
    devtool,
    entry,
    output,
    resolve,
    module: {
        rules
    },
    plugins,
    devServer,
    stats: {
        warnings: false
    },
    mode: IS_PRODUCTION ? 'production' : 'development'
};
