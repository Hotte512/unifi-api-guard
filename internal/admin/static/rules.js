// Optional helpers for the rule form on the client edit page. The form works without this script.
(function () {
	'use strict';
	var list = document.querySelector('[data-rule-list]');
	if (!list) {
		return;
	}
	var form = list.closest('form');
	var count = form.querySelector('input[name=rule_count]');
	var max = parseInt(list.getAttribute('data-max'), 10) || 200;
	var addButton = form.querySelector('[data-add-rule]');

	function setMode(mode) {
		var radio = form.querySelector('input[name=rules_mode][value=' + mode + ']');
		if (radio) {
			radio.checked = true;
		}
	}

	// show the path input only for "Eigener Pfad" and disable methods the endpoint does not support
	function update(card) {
		var select = card.querySelector('select.rule-endpoint');
		var option = select.options[select.selectedIndex];
		var path = card.querySelector('.rule-path');
		path.hidden = select.value !== 'custom';
		var supported = option && option.getAttribute('data-methods');
		var allowed = supported ? supported.split(' ') : null;
		card.querySelectorAll('input.rule-method').forEach(function (box) {
			var ok = !allowed || allowed.indexOf(box.value) >= 0;
			// a checked method stays enabled, otherwise it would silently be dropped on save
			box.disabled = !ok && !box.checked;
			box.parentNode.classList.toggle('unsupported', !ok);
		});
	}

	function cards() {
		return list.querySelectorAll('[data-rule]');
	}

	function updateAddButton() {
		addButton.disabled = cards().length >= max;
	}

	cards().forEach(update);

	list.addEventListener('change', function (e) {
		var card = e.target.closest('[data-rule]');
		if (card && e.target.matches('select.rule-endpoint')) {
			update(card);
		}
		if (card && e.target.matches('input.rule-method')) {
			update(card);
		}
		setMode('form');
	});
	list.addEventListener('input', function () {
		setMode('form');
	});
	var json = form.querySelector('textarea[name=rules]');
	if (json) {
		json.addEventListener('input', function () {
			setMode('json');
		});
	}

	addButton.hidden = false;
	updateAddButton();
	addButton.addEventListener('click', function () {
		var all = cards();
		if (all.length >= max) {
			return;
		}
		var n = all.length;
		var copy = all[all.length - 1].cloneNode(true);
		copy.querySelectorAll('[name]').forEach(function (el) {
			el.name = el.name.replace(/^rule\.\d+\./, 'rule.' + n + '.');
			if (el.type === 'checkbox') {
				el.checked = false;
				el.disabled = false;
			} else if (el.tagName === 'SELECT') {
				el.selectedIndex = 0;
			} else {
				el.value = '';
			}
		});
		copy.querySelector('.rule-title').textContent = 'Regel ' + (n + 1);
		list.appendChild(copy);
		count.value = String(n + 1);
		update(copy);
		updateAddButton();
		copy.querySelector('select.rule-endpoint').focus();
	});
}());
