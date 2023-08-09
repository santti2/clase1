function terminanEnA() {
  const palabras = ["a", "a", "a", "a"];
  const palabrascona = palabras.every((palabra) => palabra === "a");
  console.log(palabrascona); // -> True

  const names = ["Miguela", "Juana", "Itziara", "Isabela"];
  const palabrassina = names.every((name) => name.endsWith("a"));
  console.log(palabrassina); // -> False
}
console.log(terminanEnA());
