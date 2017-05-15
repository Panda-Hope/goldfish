<template>
  <div class="content has-text-centered">
    <p>
      <img width="200" src="~assets/logo.svg" :alt="description">
    </p>

    <h1 class="is-title is-bold">{{ name.replace('-', ' ') }}</h1>

    <p>
      <strong>{{ description }}</strong>,
      <a :href="homepage">Live Demo</a>
    </p>

    <p>Supports Vue 2.0 and Bulma 0.3!</p>
  </div>
</template>

<script>
  export default {
    data () {
      return this.$store.state.pkg
    },
    mounted: function () {
      this.$message({
        message: 'This goldfish demo is for display purposes only. While it is hooked up to a real vault instance, it should not be considered secure. Head to the Login page to authenticate first!',
        type: 'warning',
        duration: 0,
        showCloseButton: true
      })
    }
  }
</script>

<style lang="scss" scoped>
.is-title {
  text-transform: capitalize;
}
</style>
