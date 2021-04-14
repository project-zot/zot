const dictionary = {
    about: 'About',
    alert: 'Alert',
    confirmation: 'Confirmation',
};

function uncamelize(str, separator) {
    // Assume default separator is a single space.
    if (typeof (separator) === 'undefined') {
        separator = ' ';
    }
    // Replace all capital letters by separator followed by lowercase one
    str = str.replace(/[A-Z]/g, function(letter) {
        return separator + letter;
    });
    // Remove first separator
    return str.replace('/^' + separator + '/', '');
}

function capitalizeFirstLetter(string) {
    if (string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
}

/*
 * Proxy should guarantee the user will get a
 * String, either the value of the target[property]
 * or the property string. no chance of getting
 * undefined
 * @type {Proxy}
 */
const labels = new Proxy(dictionary, {
    get: function(target, property) {
        return property in target ? target[property] : capitalizeFirstLetter(uncamelize(property));
    }
});

export default labels;
